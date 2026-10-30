package gateway

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestChatGatewayBlocksMasksAndPreservesProtocol(t *testing.T) {
	for _, target := range []struct{ base, path string }{
		{"", "/v1/chat/completions"},
		{"/v1", "/v1/chat/completions"},
		{"/v1/", "/v1/chat/completions"},
		{"/proxy/v1/", "/proxy/v1/chat/completions"},
		{"/proxy/", "/proxy/v1/chat/completions"},
	} {
		for _, requestPath := range []string{chatCompletionsPath, chatCompletionsAliasPath} {
			t.Run(target.base+requestPath, func(t *testing.T) {
				calls := 0
				sse := "data: {\"choices\":[{\"delta\":{\"content\":\"OK\"}}]}\n\ndata: [DONE]\n\n"
				const normalResponse = `{"choices":[{"message":{"role":"assistant","content":"OK"}}]}`
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					if r.URL.Path != target.path {
						t.Errorf("上游路径=%s，期望 %s", r.URL.Path, target.path)
					}
					body, _ := io.ReadAll(r.Body)
					if strings.Contains(string(body), "内部系统A") || !strings.Contains(string(body), "业务系统") {
						t.Errorf("上游脱敏内容错误: %s", body)
					}
					if strings.Contains(string(body), `"stream":true`) {
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = io.WriteString(w, sse)
					} else {
						w.Header().Set("Content-Type", "application/json")
						_, _ = io.WriteString(w, normalResponse)
					}
				}))
				defer upstream.Close()
				auditor := &memoryAuditor{failAfter: -1}
				handler := newTestHandler(t, upstream.URL+target.base, auditor, []storage.Rule{
					{ID: "block", Type: "keyword", Action: "block", Enabled: true, Keywords: []string{"客户A"}},
					{ID: "mask", Type: "keyword_mapping", Action: "mask", Enabled: true, Mappings: []storage.Mapping{{Source: "内部系统A", Target: "业务系统"}}},
				})
				handler.requestLog = &RequestLog{}
				handler.requestLog.SetEnabled(true)
				perform := func(body string) *httptest.ResponseRecorder {
					r := httptest.NewRequest(http.MethodPost, requestPath, bytes.NewBufferString(body))
					r.Header.Set("Authorization", "Bearer "+handler.localToken)
					r.Header.Set("Content-Type", "application/json")
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, r)
					if r.URL.Path != requestPath {
						t.Fatal("别名处理不应修改调用者持有的请求")
					}
					return w
				}
				blocked := perform(`{"messages":[{"role":"tool","tool_call_id":"1","content":"客户A"}]}`)
				if blocked.Code != http.StatusForbidden || calls != 0 {
					t.Fatalf("阻断失败: status=%d calls=%d", blocked.Code, calls)
				}
				invalid := perform(`{"messages":[{"role":"user","content":"normal","future_text":"客户A"}]}`)
				if invalid.Code != http.StatusForbidden || calls != 0 {
					t.Fatalf("扩展字段中的违禁内容到达上游: status=%d calls=%d", invalid.Code, calls)
				}
				masked := perform(`{"model":"gpt-test","messages":[{"role":"user","content":"内部系统A"}],"stream":true}`)
				if masked.Code != http.StatusOK || masked.Body.String() != sse || calls != 1 {
					t.Fatalf("Chat SSE 透传失败: status=%d calls=%d body=%s", masked.Code, calls, masked.Body.String())
				}
				normal := perform(`{"model":"gpt-test","messages":[{"role":"user","content":"内部系统A"}]}`)
				if normal.Code != http.StatusOK || normal.Body.String() != normalResponse || calls != 2 {
					t.Fatalf("Chat JSON 透传失败: status=%d calls=%d body=%s", normal.Code, calls, normal.Body.String())
				}
				if len(auditor.events) != 6 || auditor.events[0].Action != "block" || auditor.events[2].Action != "mask" {
					t.Fatalf("Chat 路径应执行相同审计: %+v", auditor.events)
				}
				for _, entry := range handler.requestLog.Snapshot().Items {
					if entry.Path != requestPath || !entry.Finished {
						t.Fatalf("实时日志丢失原始路径或结束状态: %+v", entry)
					}
				}
			})
		}
	}
}
