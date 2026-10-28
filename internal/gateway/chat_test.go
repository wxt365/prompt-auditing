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
	for _, base := range []string{"", "/v1", "/v1/", "/proxy/v1/"} {
		t.Run(base, func(t *testing.T) {
			calls := 0
			sse := "data: {\"choices\":[{\"delta\":{\"content\":\"OK\"}}]}\n\ndata: [DONE]\n\n"
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				wantPath := strings.TrimRight(base, "/") + "/chat/completions"
				if base == "" {
					wantPath = chatCompletionsPath
				}
				if r.URL.Path != wantPath {
					t.Errorf("上游路径=%s，期望 %s", r.URL.Path, wantPath)
				}
				body, _ := io.ReadAll(r.Body)
				if strings.Contains(string(body), "内部系统A") || !strings.Contains(string(body), "业务系统") {
					t.Errorf("上游脱敏内容错误: %s", body)
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, sse)
			}))
			defer upstream.Close()
			handler := newTestHandler(t, upstream.URL+base, &memoryAuditor{failAfter: -1}, []storage.Rule{
				{ID: "block", Type: "keyword", Action: "block", Enabled: true, Keywords: []string{"客户A"}},
				{ID: "mask", Type: "keyword_mapping", Action: "mask", Enabled: true, Mappings: []storage.Mapping{{Source: "内部系统A", Target: "业务系统"}}},
			})
			perform := func(body string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodPost, chatCompletionsPath, bytes.NewBufferString(body))
				r.Header.Set("Authorization", "Bearer "+handler.localToken)
				r.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
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
		})
	}
}
