//go:build !windows

package integration_test

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/config"
	"github.com/xiaotaowang/prompt-auditing/internal/gateway"
	"github.com/xiaotaowang/prompt-auditing/internal/security"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
	_ "modernc.org/sqlite"
)

const (
	integrationLocalToken  = "integration-local-token-at-least-32"
	integrationUpstreamKey = "sk-INTEGRATIONUPSTREAMKEY1234"
)

func TestGatewayUsesPolicyAndAuditDatabasesEndToEnd(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(t.TempDir(), "data")
	policyPath := filepath.Join(directory, "policy.db")
	auditPath := filepath.Join(directory, "audit.db")
	if err := storage.InitDatabases(ctx, policyPath, auditPath); err != nil {
		t.Fatal(err)
	}
	policy, err := storage.OpenPolicy(ctx, policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.AddBlock(ctx, "keyword.block", []string{"客户A", "项目B", integrationLocalToken}, false); err != nil {
		t.Fatal(err)
	}
	if err := policy.AddReplacement(ctx, "keyword.mask", []storage.Mapping{{Source: "内部系统A", Target: "业务系统"}}, false); err != nil {
		t.Fatal(err)
	}
	rules, err := policy.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Close(); err != nil {
		t.Fatal(err)
	}
	engine, err := security.NewEngine(rules)
	if err != nil {
		t.Fatal(err)
	}
	auditStore, err := storage.OpenAudit(ctx, auditPath, 30, 100<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer auditStore.Close()

	var upstreamCalls atomic.Int32
	upstreamBodies := make(chan string, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstreamCalls.Add(1)
		body, _ := io.ReadAll(request.Body)
		upstreamBodies <- string(body)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	handler, err := gateway.NewHandler(gateway.Options{
		Upstream: upstreamURL, Client: upstream.Client(), Engine: engine, Audit: auditStore,
		LocalToken: integrationLocalToken, UpstreamKey: integrationUpstreamKey,
		OSUser: "developer", Limits: config.LimitsConfig{
			MaxCompressedBytes: 1 << 20, MaxDecompressedBytes: 1 << 20, MaxConcurrent: 10,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	blocked := request(t, handler, `{"model":"gpt-test","input":"客户A 项目B 客户A"}`)
	if blocked.Code != http.StatusForbidden || upstreamCalls.Load() != 0 {
		t.Fatalf("阻断失败: status=%d calls=%d body=%s", blocked.Code, upstreamCalls.Load(), blocked.Body.String())
	}
	record, err := auditStore.LatestBlocked(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if record.RequestID != blocked.Header().Get("x-gateway-request-id") ||
		strings.Join(record.MatchedKeywords, ",") != "客户A,项目B" || !bytes.Contains(record.RequestBody, []byte("客户A")) {
		t.Fatalf("阻断审计不可追溯: %#v", record)
	}

	masked := request(t, handler, `{"model":"gpt-test","input":"调用内部系统A"}`)
	if masked.Code != http.StatusOK || upstreamCalls.Load() != 1 {
		t.Fatalf("脱敏转发失败: status=%d calls=%d", masked.Code, upstreamCalls.Load())
	}
	forwarded := <-upstreamBodies
	if strings.Contains(forwarded, "内部系统A") || !strings.Contains(forwarded, "业务系统") {
		t.Fatalf("上游正文未正确脱敏: %s", forwarded)
	}

	credentialBlocked := request(t, handler, `{"model":"gpt-test","input":"`+integrationLocalToken+` `+integrationUpstreamKey+`"}`)
	if credentialBlocked.Code != http.StatusForbidden || upstreamCalls.Load() != 1 {
		t.Fatalf("凭证请求未阻断: status=%d calls=%d body=%s", credentialBlocked.Code, upstreamCalls.Load(), credentialBlocked.Body.String())
	}

	forceMatchFailure(t, auditPath)
	failed := request(t, handler, `{"model":"gpt-test","input":"客户A"}`)
	if failed.Code != http.StatusServiceUnavailable || upstreamCalls.Load() != 1 {
		t.Fatalf("审计失败未关闭请求: status=%d calls=%d body=%s", failed.Code, upstreamCalls.Load(), failed.Body.String())
	}
	assertNoAuditEvent(t, auditPath, failed.Header().Get("x-gateway-request-id"))
	assertAuditFilesDoNotContainCredentials(t, auditPath, integrationLocalToken, integrationUpstreamKey, "Authorization")
}

func assertAuditFilesDoNotContainCredentials(t *testing.T, path string, forbidden ...string) {
	t.Helper()
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		data, err := os.ReadFile(candidate)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		for _, value := range forbidden {
			if bytes.Contains(data, []byte(value)) {
				t.Fatalf("审计文件 %s 包含禁止内容 %q", candidate, value)
			}
		}
	}
}

func request(t *testing.T, handler http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+integrationLocalToken)
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func forceMatchFailure(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteFileURL(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER force_match_failure BEFORE INSERT ON audit_matches
		BEGIN SELECT RAISE(ABORT, 'forced match failure'); END`); err != nil {
		t.Fatal(err)
	}
}

func assertNoAuditEvent(t *testing.T, path, requestID string) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteFileURL(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE request_id = ?", requestID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("失败事务留下主事件: %d", count)
	}
}

func sqliteFileURL(path string) string {
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(path)}).String()
}
