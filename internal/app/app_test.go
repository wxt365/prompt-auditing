package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"version"}, &stdout, &stderr, BuildInfo{Version: "1.2.3", Commit: "abc123"})
	if code != 0 || stdout.String() != "codex-gateway 1.2.3 (abc123)\n" || stderr.Len() != 0 {
		t.Fatalf("version 输出错误: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestInitAndCheckConfig(t *testing.T) {
	configPath := writeTestConfig(t, t.TempDir())
	stdout, stderr, code := runForTest([]string{"init", "--config", configPath})
	if code != 0 || !strings.Contains(stdout, "初始化完成") || stderr != "" {
		t.Fatalf("init 输出错误: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	stdout, stderr, code = runForTest([]string{"check-config", "--config", configPath})
	if code != 0 || !strings.Contains(stdout, "规则版本=1") || !strings.Contains(stdout, "规则数量=5") || stderr != "" {
		t.Fatalf("check-config 输出错误: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	_, _, code = runForTest([]string{"init", "--config", configPath})
	if code != 1 {
		t.Fatal("重复 init 必须拒绝覆盖数据库")
	}
}

func TestStartAndCheckConfigRejectEmptiedDatabases(t *testing.T) {
	for _, command := range []string{"check-config", "start"} {
		for _, databaseName := range []string{"policy.db", "audit.db"} {
			t.Run(command+"/"+databaseName, func(t *testing.T) {
				directory := t.TempDir()
				configPath := writeTestConfig(t, directory)
				if _, stderr, code := runForTest([]string{"init", "--config", configPath}); code != 0 {
					t.Fatal(stderr)
				}
				if err := os.Truncate(filepath.Join(directory, "data", databaseName), 0); err != nil {
					t.Fatal(err)
				}
				if command == "start" {
					t.Setenv("CODEX_GATEWAY_TOKEN", "local-token-with-at-least-32-bytes")
					t.Setenv("OPENAI_API_KEY", "different-upstream-key")
				}
				stdout, stderr, code := runForTest([]string{command, "--config", configPath})
				if code != 1 || stdout != "" || !strings.Contains(stderr, "必须先执行 init") {
					t.Fatalf("空数据库未失败关闭: code=%d stdout=%q stderr=%q", code, stdout, stderr)
				}
			})
		}
	}
}

func TestPolicyCRUDIsPersistedAndVersioned(t *testing.T) {
	configPath := writeTestConfig(t, t.TempDir())
	if _, stderr, code := runForTest([]string{"init", "--config", configPath}); code != 0 {
		t.Fatal(stderr)
	}
	commands := [][]string{
		{"policy", "add-block", "--config", configPath, "--id", "keyword.customer", "--keyword", "客户A", "--keyword", "项目B"},
		{"policy", "add-replacement", "--config", configPath, "--id", "mapping.system", "--mapping", "内部系统A=业务系统"},
		{"policy", "add-regex", "--config", configPath, "--id", "regex.custom", "--action", "block", "--pattern", `token-[0-9]+`, "--case-sensitive"},
		{"policy", "add-private-ipv4", "--config", configPath, "--id", "network.private-custom", "--action", "warn"},
		{"policy", "disable", "--config", configPath, "--id", "keyword.customer"},
		{"policy", "enable", "--config", configPath, "--id", "keyword.customer"},
	}
	for _, command := range commands {
		if _, stderr, code := runForTest(command); code != 0 {
			t.Fatalf("命令失败 %v: %s", command, stderr)
		}
	}
	stdout, stderr, code := runForTest([]string{"policy", "list", "--config", configPath})
	if code != 0 || stderr != "" {
		t.Fatalf("policy list 失败: %s", stderr)
	}
	var set storage.RuleSet
	if err := json.Unmarshal([]byte(stdout), &set); err != nil {
		t.Fatal(err)
	}
	if set.Version != "7" || len(set.Rules) != 9 {
		t.Fatalf("规则快照错误: %#v", set)
	}
	for _, rule := range set.Rules {
		if rule.ID == "regex.custom" && !rule.CaseSensitive {
			t.Fatal("add-regex 未持久化 --case-sensitive")
		}
	}
	if _, stderr, code := runForTest([]string{"policy", "delete", "--config", configPath, "--id", "keyword.customer"}); code != 0 {
		t.Fatal(stderr)
	}
}

func TestStartRejectsMissingEnvironmentSecrets(t *testing.T) {
	configPath := writeTestConfig(t, t.TempDir())
	if _, stderr, code := runForTest([]string{"init", "--config", configPath}); code != 0 {
		t.Fatal(stderr)
	}
	t.Setenv("CODEX_GATEWAY_TOKEN", "")
	t.Setenv("OPENAI_API_KEY", "")
	stdout, stderr, code := runForTest([]string{"start", "--config", configPath})
	if code != 1 || !strings.Contains(stderr, "CODEX_GATEWAY_TOKEN") {
		t.Fatalf("缺少密钥响应错误: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestUpstreamClientRejectsInvalidAdditionalRootCertificate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid-ca.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", path)
	if _, err := newUpstreamHTTPClient(time.Second); err == nil {
		t.Fatal("无效 SSL_CERT_FILE 必须拒绝启动")
	}
}

func TestUpstreamClientUsesBoundedConnectionTimeouts(t *testing.T) {
	t.Setenv("SSL_CERT_FILE", "")
	client, err := newUpstreamHTTPClient(30 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("上游 Transport 类型错误: %T", client.Transport)
	}
	if transport.DialContext == nil || transport.TLSHandshakeTimeout <= 0 ||
		transport.ResponseHeaderTimeout != 30*time.Second || transport.IdleConnTimeout <= 0 {
		t.Fatalf("上游连接超时配置不完整: %#v", transport)
	}
}

func TestStartDoesNotReportStartedWhenListenFails(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	configPath := writeTestConfigWithListen(t, t.TempDir(), listener.Addr().String())
	if _, stderr, code := runForTest([]string{"init", "--config", configPath}); code != 0 {
		t.Fatal(stderr)
	}
	t.Setenv("CODEX_GATEWAY_TOKEN", "local-token-with-at-least-32-bytes")
	t.Setenv("OPENAI_API_KEY", "different-upstream-key")
	stdout, stderr, code := runForTest([]string{"start", "--config", configPath})
	if code != 1 || strings.Contains(stdout, "Gateway 已启动") || !strings.Contains(stderr, "监听 Gateway 地址") {
		t.Fatalf("监听失败输出错误: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestStartWarnsWhenUpstreamUsesHTTP(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	directory := t.TempDir()
	configPath := writeTestConfigWithListen(t, directory, listener.Addr().String())
	body, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	body = bytes.Replace(body, []byte("https://api.openai.com/v1"), []byte("http://192.168.137.250:33000/v1/"), 1)
	if err := os.WriteFile(configPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := runForTest([]string{"init", "--config", configPath}); code != 0 {
		t.Fatal(stderr)
	}
	t.Setenv("CODEX_GATEWAY_TOKEN", "local-token-with-at-least-32-bytes")
	t.Setenv("OPENAI_API_KEY", "different-upstream-key")
	stdout, stderr, code := runForTest([]string{"start", "--config", configPath})
	if code != 1 || strings.Contains(stdout, "Gateway 已启动") ||
		!strings.Contains(stderr, "upstream 使用 HTTP") || !strings.Contains(stderr, "明文传输") {
		t.Fatalf("HTTP upstream 警告错误: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func runForTest(args []string) (string, string, int) {
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr, BuildInfo{})
	return stdout.String(), stderr.String(), code
}

func writeTestConfig(t *testing.T, directory string) string {
	return writeTestConfigWithListen(t, directory, "127.0.0.1:18080")
}

func writeTestConfigWithListen(t *testing.T, directory, listen string) string {
	t.Helper()
	body := fmt.Sprintf(`version: 1
listen: %s
upstream: https://api.openai.com/v1
policy_db: data/policy.db
audit_db: data/audit.db
max_body_bytes: 5242880
max_concurrent_requests: 10
audit_retention_days: 30
audit_max_bytes: 104857600
`, listen)
	path := filepath.Join(directory, "gateway.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
