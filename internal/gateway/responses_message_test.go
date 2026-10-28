package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestResponsesMessagesWithoutTypePreserveForwardingAndSecurity(t *testing.T) {
	for _, scenario := range []string{"allow", "mask", "block", "invalid"} {
		t.Run(scenario, func(t *testing.T) {
			const token = "message-preview-token"
			const sse = "event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n"
			forwarded := make(chan []byte, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				forwarded <- body
				if r.URL.Path != responsesPath || r.Header.Get("Authorization") != "Bearer "+token {
					t.Error("请求路径或认证信息未保留")
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, sse)
			}))
			defer upstream.Close()
			auditor := &memoryAuditor{failAfter: -1}
			handler := newClientAuthHandler(t, upstream.URL+"/v1", auditor, []storage.Rule{
				{ID: "mask", Type: "keyword_mapping", Action: "mask", Enabled: true, Mappings: []storage.Mapping{{Source: "stage_source_7f3", Target: "stage_safe_7f3"}}},
				{ID: "block", Type: "keyword", Action: "block", Enabled: true, Keywords: []string{"stage_source_7f3", "stage_denied_7f3"}},
			})
			text := "normal preview text"
			if scenario == "mask" || scenario == "block" {
				text = "stage_source_7f3"
			}
			if scenario == "block" {
				text += " stage_denied_7f3"
			}
			message := map[string]any{"role": "user", "content": text}
			if scenario == "invalid" {
				message["hidden"] = "stage_denied_7f3"
			}
			raw, _ := json.Marshal(map[string]any{"model": "preview-model", "stream": true, "input": []any{message}})
			request := httptest.NewRequest(http.MethodPost, responsesPath, bytes.NewReader(raw))
			request.Header.Set("Authorization", "Bearer "+token)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			switch scenario {
			case "block", "invalid":
				status := http.StatusForbidden
				if response.Code != status || len(forwarded) != 0 {
					t.Fatalf("请求未在本地正确拒绝: HTTP %d", response.Code)
				}
				if scenario == "block" && (len(auditor.events) != 1 || auditor.events[0].Result != "blocked" || !bytes.Equal(auditor.events[0].RequestBody, raw)) {
					t.Fatal("阻断审计未保留原始请求")
				}
			default:
				if response.Code != http.StatusOK || response.Body.String() != sse || len(forwarded) != 1 {
					t.Fatalf("简写消息未正常转发并返回流式响应: HTTP %d", response.Code)
				}
				body := <-forwarded
				if scenario == "allow" && !bytes.Equal(body, raw) {
					t.Fatal("无需替换时应原样转发正文")
				}
				var payload map[string]any
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatal(err)
				}
				got := payload["input"].([]any)[0].(map[string]any)
				if _, exists := got["type"]; exists {
					t.Fatal("网关不应补写消息 type")
				}
				if scenario == "mask" && (got["content"] != "stage_safe_7f3" || auditor.events[0].Action != "mask") {
					t.Fatal("简写消息未先替换再放行")
				}
			}
		})
	}
}
