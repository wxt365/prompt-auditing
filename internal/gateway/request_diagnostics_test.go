package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestRejectedEndpointsPersistDiagnosticsWithoutLiveCapture(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(t.TempDir(), "data")
	path := filepath.Join(directory, "audit.db")
	if err := storage.InitDatabases(ctx, filepath.Join(directory, "policy.db"), path); err != nil {
		t.Fatal(err)
	}
	store, err := storage.OpenAudit(ctx, path, 30, 100<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	handler := newTestHandler(t, upstream.URL, store, nil)
	logs := &RequestLog{}
	handler.requestLog = logs
	var records []storage.AuditRecord
	for _, enabled := range []bool{false, true} {
		logs.SetEnabled(enabled)
		for _, test := range []struct {
			method, path, loggedPath string
			status                   int
			unauthorized, upgrade    bool
		}{
			{method: "POST", path: "/v1/alpha/search", loggedPath: "/v1/alpha/search", status: 404},
			{method: "POST", path: "/v2/images/edits", loggedPath: "/v2/images/edits", status: 404},
			{method: "GET", path: "/chat/completions", loggedPath: "/chat/completions", status: 405},
			{method: "GET", path: "/responses", loggedPath: "/responses", status: 405},
			{method: "POST", path: responsesPath + "?api_key=query-private-value", loggedPath: responsesPath, status: 404},
			{method: "POST", path: "/v1/alpha/search", loggedPath: "/v1/alpha/search", status: 401, unauthorized: true},
			{method: "POST", path: responsesPath, loggedPath: responsesPath, status: 400, upgrade: true},
			{method: "POST", path: "/v1/" + testLocalToken + "/search", loggedPath: "/v1/" + redactedCredential + "/search", status: 404},
			{method: "POST", path: "/v1/%75pstream-key/search", loggedPath: "/v1/" + redactedCredential + "/search", status: 404},
		} {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(`{"input":"request-body-secret"}`))
			if !test.unauthorized {
				request.Header.Set("Authorization", "Bearer "+testLocalToken)
			}
			if test.upgrade {
				request.Header.Set("Connection", "Upgrade")
				request.Header.Set("Upgrade", "websocket")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("%s %s: 状态码=%d", test.method, test.path, response.Code)
			}
			page, err := storage.QueryAudit(ctx, path, storage.AuditFilter{RequestID: response.Header().Get("x-gateway-request-id")})
			if err != nil || len(page.Items) != 1 {
				t.Fatalf("拒绝日志未持久化: %+v %v", page, err)
			}
			record := page.Items[0]
			if record.RequestMethod != test.method || record.RequestPath != test.loggedPath || record.HTTPStatus != test.status || record.Result != "rejected" {
				t.Fatalf("拒绝诊断不完整: %+v", record)
			}
			records = append(records, record)
			body, err := storage.QueryAuditRequestBody(ctx, path, record.ID)
			if err != nil || body.Body != "" {
				t.Fatalf("接口拒绝不应保存正文: %+v %v", body, err)
			}
			if enabled {
				item := logs.Snapshot().Items[0]
				if item.Path != test.loggedPath || item.Method != test.method || item.Status != test.status || item.ErrorCode != record.ErrorCode || !item.Finished {
					t.Fatalf("实时日志与审计不一致: %+v %+v", item, record)
				}
			} else if len(logs.Snapshot().Items) != 0 {
				t.Fatal("未开启采集时不应保存实时日志")
			}
		}
	}
	if calls.Load() != 0 {
		t.Fatal("拒绝的请求被发送到上游")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		detail, err := storage.QueryAuditDetail(ctx, path, record.ID)
		if err != nil || detail.RequestMethod != record.RequestMethod || detail.RequestPath != record.RequestPath || detail.HTTPStatus != record.HTTPStatus {
			t.Fatalf("关闭数据库后诊断未保留: %+v %v", detail, err)
		}
		serialized, _ := json.Marshal(detail)
		for _, secret := range []string{testLocalToken, "upstream-key", "query-private-value", "request-body-secret", "Authorization"} {
			if strings.Contains(string(serialized), secret) {
				t.Fatalf("拒绝日志泄露凭证或正文: %s", serialized)
			}
		}
	}
}

func TestDiagnosticPathRedactsSensitiveSegments(t *testing.T) {
	for _, test := range []struct{ path, want string }{
		{"/v1/alpha/search", "/v1/alpha/search"},
		{"/v1/embeddings/", "/v1/embeddings/"},
		{"/v1/token/private-value/search", "/v1/token/" + redactedCredential + "/search"},
		{"/v1/sk-not-configured/search", "/v1/" + redactedCredential + "/search"},
		{"/v1/" + strings.Repeat("a", 64), "/v1/" + redactedCredential},
		{"/v1/客户A/search", "/v1/" + redactedCredential + "/search"},
		{"/v1/bad\nline/search", "/v1/" + redactedCredential + "/search"},
		{"/v1/%2573ecret/search?token=private-value", "/v1/" + redactedCredential + "/search"},
	} {
		if got := diagnosticPath(test.path, "secret"); got != test.want {
			t.Fatalf("路径=%q，结果=%q，期望=%q", test.path, got, test.want)
		}
	}
	if got := diagnosticPath(strings.Repeat("/segment", 200)); len([]rune(got)) > 513 {
		t.Fatal("诊断路径超过长度上限")
	}
}
