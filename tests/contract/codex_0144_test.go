//go:build codex_contract

package contract_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/audit"
	"github.com/xiaotaowang/prompt-auditing/internal/config"
	"github.com/xiaotaowang/prompt-auditing/internal/gateway"
	"github.com/xiaotaowang/prompt-auditing/internal/security"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

type contractAuditor struct {
	mu      sync.Mutex
	events  []audit.Event
	healthy bool
}

func (a *contractAuditor) Write(event audit.Event) error {
	a.mu.Lock()
	a.events = append(a.events, event)
	a.mu.Unlock()
	return nil
}

func (a *contractAuditor) Fingerprint([]byte) string { return "contract-fingerprint" }
func (a *contractAuditor) Healthy() bool             { return a.healthy }
func (a *contractAuditor) MarkUnhealthy()            { a.healthy = false }

func TestCodex0144ResponsesContract(t *testing.T) {
	if os.Getenv("RUN_CODEX_CONTRACT") != "1" {
		t.Skip("设置 RUN_CODEX_CONTRACT=1 后运行真实 Codex 契约测试")
	}
	if _, err := exec.LookPath("codex"); err != nil {
		t.Skip("当前环境没有 codex CLI")
	}

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/responses" {
			t.Errorf("上游路径 = %s", request.URL.Path)
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, successfulSSE())
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := security.NewEngine(storage.RuleSet{
		Version: "1", DefaultAction: storage.DefaultAction,
	})
	if err != nil {
		t.Fatal(err)
	}
	auditor := &contractAuditor{healthy: true}
	handler, err := gateway.NewHandler(gateway.Options{
		Upstream: upstreamURL, Client: upstream.Client(), Engine: engine, Audit: auditor,
		LocalToken: "contract-local-token-at-least-32-bytes", UpstreamKey: "contract-upstream-key",
		Limits: config.LimitsConfig{MaxCompressedBytes: 5 << 20, MaxDecompressedBytes: 5 << 20, MaxConcurrent: 10},
	})
	if err != nil {
		t.Fatal(err)
	}

	var captured []byte
	localGateway := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		original, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Error(readErr)
			return
		}
		captured = decodeForCapture(t, original, request.Header.Get("Content-Encoding"))
		request.Body = io.NopCloser(bytes.NewReader(original))
		request.ContentLength = int64(len(original))
		handler.ServeHTTP(writer, request)
	}))
	defer localGateway.Close()

	provider := fmt.Sprintf(`{name="Codex Security Gateway",base_url=%q,env_key="CODEX_GATEWAY_TOKEN",wire_api="responses",request_max_retries=0,stream_max_retries=0}`, localGateway.URL+"/v1")
	command := exec.Command("codex", "exec", "--ephemeral", "--ignore-user-config", "--skip-git-repo-check", "--json",
		"-c", `model_provider="security_gateway"`,
		"-c", `model="gpt-5.2-codex"`,
		"-c", "model_providers.security_gateway="+provider,
		"仅回复 OK")
	command.Env = append(os.Environ(),
		"CODEX_HOME="+t.TempDir(),
		"CODEX_GATEWAY_TOKEN=contract-local-token-at-least-32-bytes",
	)
	output, commandErr := command.CombinedOutput()
	if len(captured) == 0 {
		t.Fatalf("Codex 未向 Gateway 发送请求: %v\n%s", commandErr, output)
	}
	var root map[string]any
	if err := json.Unmarshal(captured, &root); err != nil {
		t.Fatalf("捕获的请求不是 JSON: %v", err)
	}
	keys := make([]string, 0, len(root))
	for key := range root {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	t.Logf("Codex 0.144.5 请求字段: %s", strings.Join(keys, ", "))
	if metadata, ok := root["client_metadata"].(map[string]any); ok {
		t.Logf("client_metadata 字段: %s", strings.Join(sortedKeys(metadata), ", "))
	}
	if tools, ok := root["tools"].([]any); ok {
		for index, item := range tools {
			tool, ok := item.(map[string]any)
			if !ok {
				t.Logf("tools/%d 类型: %T", index, item)
				continue
			}
			t.Logf("tools/%d type=%v 字段=%s", index, tool["type"], strings.Join(sortedKeys(tool), ", "))
		}
	}
	if _, err := security.Extract(captured); err != nil {
		t.Fatalf("Gateway 不支持当前 Codex 请求契约: %v", err)
	}
	if commandErr != nil {
		t.Fatalf("Codex 契约请求失败: %v\n%s", commandErr, output)
	}
	if !bytes.Contains(output, []byte("OK")) {
		t.Fatalf("Codex 未收到假上游响应: %s", output)
	}
}

func sortedKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func decodeForCapture(t *testing.T, body []byte, encoding string) []byte {
	t.Helper()
	if encoding != "gzip" {
		return append([]byte(nil), body...)
	}
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func successfulSSE() string {
	itemInProgress := map[string]any{
		"id": "msg_contract", "type": "message", "status": "in_progress", "role": "assistant", "content": []any{},
	}
	partInProgress := map[string]any{"type": "output_text", "annotations": []any{}, "text": ""}
	partComplete := map[string]any{"type": "output_text", "annotations": []any{}, "text": "OK"}
	itemComplete := map[string]any{
		"id": "msg_contract", "type": "message", "status": "completed", "role": "assistant",
		"content": []any{partComplete},
	}
	response := map[string]any{
		"id": "resp_contract", "object": "response", "created_at": time.Now().Unix(),
		"status": "completed", "error": nil, "incomplete_details": nil,
		"instructions": nil, "max_output_tokens": nil, "model": "gpt-5.2-codex",
		"output":              []any{itemComplete},
		"parallel_tool_calls": true, "previous_response_id": nil,
		"reasoning": map[string]any{"effort": nil, "summary": nil}, "store": false,
		"temperature": 1, "text": map[string]any{"format": map[string]any{"type": "text"}},
		"tool_choice": "auto", "tools": []any{}, "top_p": 1, "truncation": "disabled",
		"usage": map[string]any{
			"input_tokens": 1, "input_tokens_details": map[string]any{"cached_tokens": 0},
			"output_tokens": 1, "output_tokens_details": map[string]any{"reasoning_tokens": 0}, "total_tokens": 2,
		},
	}
	events := []map[string]any{
		{"type": "response.output_item.added", "output_index": 0, "item": itemInProgress, "sequence_number": 1},
		{"type": "response.content_part.added", "item_id": "msg_contract", "output_index": 0, "content_index": 0, "part": partInProgress, "sequence_number": 2},
		{"type": "response.output_text.delta", "item_id": "msg_contract", "output_index": 0, "content_index": 0, "delta": "OK", "logprobs": []any{}, "sequence_number": 3},
		{"type": "response.output_text.done", "item_id": "msg_contract", "output_index": 0, "content_index": 0, "text": "OK", "logprobs": []any{}, "sequence_number": 4},
		{"type": "response.content_part.done", "item_id": "msg_contract", "output_index": 0, "content_index": 0, "part": partComplete, "sequence_number": 5},
		{"type": "response.output_item.done", "output_index": 0, "item": itemComplete, "sequence_number": 6},
		{"type": "response.completed", "response": response, "sequence_number": 7},
	}
	var builder strings.Builder
	for _, event := range events {
		body, _ := json.Marshal(event)
		fmt.Fprintf(&builder, "event: %s\ndata: %s\n\n", event["type"], body)
	}
	return builder.String()
}
