//go:build native_e2e && windows

package e2e_test

import (
	"bytes"
	"crypto/x509"
	"database/sql"
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
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	_ "modernc.org/sqlite"
)

const windowsE2EToken = "windows-e2e-local-token-at-least-32-bytes"

type windowsCapturedRequest struct {
	authorization string
	body          string
}

func TestWindowsArtifactCore(t *testing.T) {
	binary := os.Getenv("GATEWAY_BINARY")
	if binary == "" {
		t.Skip("设置 GATEWAY_BINARY 后运行原生 Windows 产物 E2E")
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatal(err)
	}

	requests := make(chan windowsCapturedRequest, 4)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		requests <- windowsCapturedRequest{authorization: request.Header.Get("Authorization"), body: string(body)}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"ok":true}`)
	}))
	defer upstream.Close()

	directory := t.TempDir()
	caPath := filepath.Join(directory, "upstream-ca.pem")
	writeWindowsCertificate(t, caPath, upstream.Certificate())
	port := windowsAvailablePort(t)
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

	runWindowsBinary(t, binary, "init", "--config", configPath)
	runWindowsBinary(t, binary, "policy", "add-block", "--config", configPath,
		"--id", "keyword.block-e2e", "--keyword", "客户A")
	runWindowsBinary(t, binary, "policy", "add-replacement", "--config", configPath,
		"--id", "keyword.mask-e2e", "--mapping", "内部系统A=业务系统")
	runWindowsBinary(t, binary, "check-config", "--config", configPath)

	var stdout, stderr windowsLockedBuffer
	process := exec.Command(binary, "start", "--config", configPath)
	process.Env = append(os.Environ(),
		"CODEX_GATEWAY_TOKEN="+windowsE2EToken,
		"OPENAI_API_KEY=windows-e2e-upstream-key",
		"SSL_CERT_FILE="+caPath,
	)
	process.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
	process.Stdout = &stdout
	process.Stderr = &stderr
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForWindowsHealth(t, baseURL, done, &stdout, &stderr)

	blocked := windowsGatewayRequest(t, baseURL, `{"model":"gpt-test","input":"客户A"}`)
	if blocked.StatusCode != http.StatusForbidden {
		t.Fatalf("Windows 原生产物阻断状态 = %d", blocked.StatusCode)
	}
	blocked.Body.Close()
	select {
	case request := <-requests:
		t.Fatalf("阻断请求到达上游: %#v", request)
	default:
	}

	masked := windowsGatewayRequest(t, baseURL, `{"model":"gpt-test","input":"内部系统A"}`)
	if masked.StatusCode != http.StatusOK {
		t.Fatalf("Windows 原生产物脱敏状态 = %d", masked.StatusCode)
	}
	masked.Body.Close()
	forwarded := <-requests
	if forwarded.authorization != "Bearer windows-e2e-upstream-key" ||
		strings.Contains(forwarded.body, "内部系统A") || !strings.Contains(forwarded.body, "业务系统") {
		t.Fatalf("Windows 原生产物上游请求错误: %#v", forwarded)
	}

	assertWindowsBlockedAudit(t, filepath.Join(directory, "data", "audit.db"))
	if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(process.Process.Pid)); err != nil {
		_ = process.Process.Kill()
		t.Fatalf("发送 Ctrl+Break 失败: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Gateway 优雅停止失败: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
		}
	case <-time.After(15 * time.Second):
		_ = process.Process.Kill()
		t.Fatal("Gateway 未在 15 秒内优雅停止")
	}
	if !strings.Contains(stdout.String(), "Gateway 已停止") {
		t.Fatalf("缺少优雅停止证据: %s", stdout.String())
	}
}

type windowsLockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (buffer *windowsLockedBuffer) Write(data []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.b.Write(data)
}

func (buffer *windowsLockedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.b.String()
}

func runWindowsBinary(t *testing.T, binary string, args ...string) string {
	t.Helper()
	output, err := exec.Command(binary, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("命令失败 %v: %v\n%s", args, err, output)
	}
	return string(output)
}

func windowsAvailablePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func waitForWindowsHealth(t *testing.T, baseURL string, done <-chan error, stdout, stderr *windowsLockedBuffer) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
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

func windowsGatewayRequest(t *testing.T, baseURL, body string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/v1/responses", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+windowsE2EToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func assertWindowsBlockedAudit(t *testing.T, path string) {
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
		t.Fatalf("Windows 原生产物审计错误: body=%s keyword=%s", body, keyword)
	}
}

func writeWindowsCertificate(t *testing.T, path string, certificate *x509.Certificate) {
	t.Helper()
	contents := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}
