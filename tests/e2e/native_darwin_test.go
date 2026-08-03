//go:build native_e2e && darwin

package e2e_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

const e2eToken = "native-e2e-local-token-at-least-32-bytes"

type capturedRequest struct {
	Authorization string
	Body          string
}

func TestDarwinArtifactCore(t *testing.T) {
	runDarwinArtifact(t, false)
}

func TestDarwinArtifactWithRealCodex(t *testing.T) {
	if _, err := exec.LookPath("codex"); err != nil {
		t.Skip("当前环境没有 codex CLI")
	}
	runDarwinArtifact(t, true)
}

func runDarwinArtifact(t *testing.T, withRealCodex bool) {
	t.Helper()
	binary := os.Getenv("GATEWAY_BINARY")
	if binary == "" {
		t.Skip("设置 GATEWAY_BINARY 后运行原生 macOS 产物 E2E")
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatal(err)
	}

	requests := make(chan capturedRequest, 8)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := decodeRequestBody(request)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		requests <- capturedRequest{Authorization: request.Header.Get("Authorization"), Body: string(body)}
		if bytes.Contains(body, []byte(`"stream":true`)) {
			writer.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(writer, successfulSSE())
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	directory := t.TempDir()
	caPath := filepath.Join(directory, "upstream-ca.pem")
	writeServerCertificate(t, caPath, upstream.Certificate())
	port := availablePort(t)
	configPath := filepath.Join(directory, "gateway.yaml")
	configBody := fmt.Sprintf(`version: 1
listen: 127.0.0.1:%d
upstream: %s/v1
policy_db: data/policy.db
audit_db: data/audit.db
max_body_bytes: 5242880
max_concurrent_requests: 10
audit_retention_days: 30
audit_max_bytes: 104857600
`, port, upstream.URL)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}

	runBinary(t, binary, nil, "init", "--config", configPath)
	runBinary(t, binary, nil, "policy", "add-block", "--config", configPath,
		"--id", "keyword.block-e2e", "--keyword", "客户A")
	runBinary(t, binary, nil, "policy", "add-replacement", "--config", configPath,
		"--id", "keyword.mask-e2e", "--mapping", "内部系统A=业务系统")
	runBinary(t, binary, nil, "check-config", "--config", configPath)

	var stdout, stderr lockedBuffer
	process := exec.Command(binary, "start", "--config", configPath)
	process.Env = append(os.Environ(),
		"CODEX_GATEWAY_TOKEN="+e2eToken,
		"OPENAI_API_KEY=native-e2e-upstream-key",
		"SSL_CERT_FILE="+caPath,
	)
	process.Stdout = &stdout
	process.Stderr = &stderr
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForHealth(t, baseURL, done, &stdout, &stderr)

	blocked := gatewayRequest(t, baseURL, `{"model":"gpt-test","input":"客户A"}`)
	if blocked.StatusCode != http.StatusForbidden {
		t.Fatalf("原生产物阻断状态 = %d", blocked.StatusCode)
	}
	blocked.Body.Close()
	select {
	case request := <-requests:
		t.Fatalf("阻断请求到达上游: %#v", request)
	default:
	}

	masked := gatewayRequest(t, baseURL, `{"model":"gpt-test","input":"内部系统A"}`)
	if masked.StatusCode != http.StatusOK {
		t.Fatalf("原生产物脱敏状态 = %d", masked.StatusCode)
	}
	masked.Body.Close()
	forwarded := <-requests
	if forwarded.Authorization != "Bearer native-e2e-upstream-key" ||
		strings.Contains(forwarded.Body, "内部系统A") || !strings.Contains(forwarded.Body, "业务系统") {
		t.Fatalf("原生产物上游请求错误: %#v", forwarded)
	}

	assertBlockedAudit(t, filepath.Join(directory, "data", "audit.db"))
	if withRealCodex {
		runRealCodex(t, baseURL)
		codexRequest := <-requests
		if !strings.Contains(codexRequest.Body, "仅回复 OK") {
			t.Fatalf("真实 Codex 请求未到达假上游: %s", codexRequest.Body)
		}
	}

	if err := process.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Gateway 优雅停止失败: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
		}
	case <-time.After(10 * time.Second):
		_ = process.Process.Kill()
		t.Fatal("Gateway 未在 10 秒内优雅停止")
	}
	if !strings.Contains(stdout.String(), "Gateway 已停止") {
		t.Fatalf("缺少优雅停止证据: %s", stdout.String())
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (buffer *lockedBuffer) Write(data []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.b.Write(data)
}

func (buffer *lockedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.b.String()
}

func runBinary(t *testing.T, binary string, environment []string, args ...string) string {
	t.Helper()
	command := exec.Command(binary, args...)
	command.Env = append(os.Environ(), environment...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("命令失败 %v: %v\n%s", args, err, output)
	}
	return string(output)
}

func availablePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func waitForHealth(t *testing.T, baseURL string, done <-chan error, stdout, stderr *lockedBuffer) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("Gateway 启动前退出: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
		default:
		}
		response, err := http.Get(baseURL + "/healthz")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("Gateway 启动超时\nstdout=%s\nstderr=%s", stdout.String(), stderr.String())
}

func gatewayRequest(t *testing.T, baseURL, body string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/v1/responses", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+e2eToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func assertBlockedAudit(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: filepath.ToSlash(path)}).String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var body, keyword string
	if err := db.QueryRow(`SELECT e.request_body_json, m.matched_keyword FROM audit_events e
		JOIN audit_matches m ON m.event_id=e.id WHERE e.action='block' ORDER BY e.id DESC, m.ordinal LIMIT 1`).Scan(&body, &keyword); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "客户A") || keyword != "客户A" {
		t.Fatalf("原生产物审计错误: body=%s keyword=%s", body, keyword)
	}
}

func runRealCodex(t *testing.T, baseURL string) {
	t.Helper()
	codexPath, err := exec.LookPath("codex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Fatal("缺少 sandbox-exec，拒绝运行可能外联的真实 Codex 测试")
	}
	provider := fmt.Sprintf(`{name="Codex Security Gateway",base_url=%q,env_key="CODEX_GATEWAY_TOKEN",wire_api="responses",request_max_retries=0,stream_max_retries=0}`, baseURL+"/v1")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	profile := `(version 1)(allow default)(deny network-outbound (require-not (remote ip "localhost:*")))`
	args := []string{"-p", profile, codexPath, "exec", "--ephemeral", "--ignore-user-config", "--skip-git-repo-check", "--json",
		"-c", `model_provider="security_gateway"`, "-c", `model="gpt-5.2-codex"`,
		"-c", "model_providers.security_gateway=" + provider, "仅回复 OK"}
	command := exec.CommandContext(ctx, "sandbox-exec", args...)
	command.Env = append(filteredCodexEnvironment(os.Environ()),
		"CODEX_HOME="+t.TempDir(), "CODEX_GATEWAY_TOKEN="+e2eToken,
		"NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost")
	output, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("OK")) {
		t.Fatalf("真实 Codex E2E 失败: %v\n%s", err, output)
	}
}

func filteredCodexEnvironment(environment []string) []string {
	blocked := map[string]bool{
		"CODEX_HOME": true, "CODEX_GATEWAY_TOKEN": true,
		"OPENAI_API_KEY": true, "OPENAI_BASE_URL": true,
		"HTTP_PROXY": true, "HTTPS_PROXY": true, "ALL_PROXY": true,
		"http_proxy": true, "https_proxy": true, "all_proxy": true,
		"NO_PROXY": true, "no_proxy": true,
	}
	result := make([]string, 0, len(environment))
	for _, item := range environment {
		name, _, found := strings.Cut(item, "=")
		if found && !blocked[name] {
			result = append(result, item)
		}
	}
	return result
}

func decodeRequestBody(request *http.Request) ([]byte, error) {
	if request.Header.Get("Content-Encoding") != "gzip" {
		return io.ReadAll(request.Body)
	}
	reader, err := gzip.NewReader(request.Body)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func writeServerCertificate(t *testing.T, path string, certificate *x509.Certificate) {
	t.Helper()
	contents := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func successfulSSE() string {
	part := map[string]any{"type": "output_text", "annotations": []any{}, "text": "OK"}
	item := map[string]any{"id": "msg_e2e", "type": "message", "status": "completed", "role": "assistant", "content": []any{part}}
	response := map[string]any{
		"id": "resp_e2e", "object": "response", "created_at": time.Now().Unix(), "status": "completed",
		"error": nil, "incomplete_details": nil, "instructions": nil, "max_output_tokens": nil,
		"model": "gpt-5.2-codex", "output": []any{item}, "parallel_tool_calls": true,
		"previous_response_id": nil, "reasoning": map[string]any{"effort": nil, "summary": nil},
		"store": false, "temperature": 1, "text": map[string]any{"format": map[string]any{"type": "text"}},
		"tool_choice": "auto", "tools": []any{}, "top_p": 1, "truncation": "disabled",
		"usage": map[string]any{"input_tokens": 1, "input_tokens_details": map[string]any{"cached_tokens": 0},
			"output_tokens": 1, "output_tokens_details": map[string]any{"reasoning_tokens": 0}, "total_tokens": 2},
	}
	events := []map[string]any{
		{"type": "response.output_item.added", "output_index": 0, "item": map[string]any{"id": "msg_e2e", "type": "message", "status": "in_progress", "role": "assistant", "content": []any{}}, "sequence_number": 1},
		{"type": "response.content_part.added", "item_id": "msg_e2e", "output_index": 0, "content_index": 0, "part": map[string]any{"type": "output_text", "annotations": []any{}, "text": ""}, "sequence_number": 2},
		{"type": "response.output_text.delta", "item_id": "msg_e2e", "output_index": 0, "content_index": 0, "delta": "OK", "logprobs": []any{}, "sequence_number": 3},
		{"type": "response.output_text.done", "item_id": "msg_e2e", "output_index": 0, "content_index": 0, "text": "OK", "logprobs": []any{}, "sequence_number": 4},
		{"type": "response.content_part.done", "item_id": "msg_e2e", "output_index": 0, "content_index": 0, "part": part, "sequence_number": 5},
		{"type": "response.output_item.done", "output_index": 0, "item": item, "sequence_number": 6},
		{"type": "response.completed", "response": response, "sequence_number": 7},
	}
	var builder strings.Builder
	for _, event := range events {
		body, _ := json.Marshal(event)
		fmt.Fprintf(&builder, "event: %s\ndata: %s\n\n", event["type"], body)
	}
	return builder.String()
}
