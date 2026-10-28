package gateway

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestJSONExtensionsForwardingAuditAndLogs(t *testing.T) {
	for _, path := range []string{responsesPath, chatCompletionsPath} {
		for _, compressed := range []bool{false, true} {
			for _, scenario := range []string{"allow", "mask", "block_value", "block_key", "unsafe_mask", "attachment", "upstream_422"} {
				t.Run(fmt.Sprintf("%s/gzip=%t/%s", path, compressed, scenario), func(t *testing.T) {
					const credential = "probe_credential_93"
					const sse = "data: {\"probe\":true}\n\n"
					forwarded := make(chan []byte, 1)
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path != path || r.Header.Get("Authorization") != "Bearer "+credential {
							t.Error("认证或路径未保留")
						}
						var reader io.Reader = r.Body
						if r.Header.Get("Content-Encoding") == "gzip" {
							unzip, err := gzip.NewReader(r.Body)
							if err != nil {
								t.Error(err)
								return
							}
							defer unzip.Close()
							reader = unzip
						}
						body, err := io.ReadAll(reader)
						if err != nil {
							t.Error(err)
							return
						}
						forwarded <- body
						if scenario == "upstream_422" {
							w.WriteHeader(http.StatusUnprocessableEntity)
							_, _ = io.WriteString(w, `{"error":"probe_upstream_validation_93"}`)
							return
						}
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = io.WriteString(w, sse)
					}))
					defer upstream.Close()
					auditor := &memoryAuditor{failAfter: -1}
					handler := newClientAuthHandler(t, upstream.URL+"/v1", auditor, []storage.Rule{
						{ID: "probe_mask_93", Type: "keyword_mapping", Action: "mask", Enabled: true, Mappings: []storage.Mapping{{Source: "probe_source_93", Target: "probe_safe_93"}}},
						{ID: "probe_block_93", Type: "keyword", Action: "block", Enabled: true, Keywords: []string{"probe_source_93", "probe_denied_93"}},
					})
					logs := &RequestLog{}
					logs.SetEnabled(true)
					handler.requestLog = logs
					metadata := map[string]any{"nested": []any{map[string]any{"text": "probe_value_93"}}, "flag": true, "empty": nil}
					text := "probe_text_93"
					switch scenario {
					case "mask":
						text = "probe_source_93"
					case "block_value":
						metadata["nested"] = []any{map[string]any{"text": "probe_denied_93"}}
					case "block_key":
						metadata["probe_denied_93"] = "normal"
					case "unsafe_mask":
						metadata["nested"] = []any{map[string]any{"text": "probe_source_93"}}
					case "attachment":
						metadata["nested"] = map[string]any{"file_data": "probe_attachment_93"}
					}
					items := make([]any, 16)
					for index := range items {
						items[index] = map[string]any{"role": "user", "content": "probe_history_93"}
					}
					items = append(items, map[string]any{"role": "user", "content": text, "metadata": metadata})
					payload := map[string]any{"model": "probe_model_93", "stream": true, "future_options": map[string]any{"nested": []any{"probe_option_93"}, "enabled": true}, "input": items}
					if path == chatCompletionsPath {
						delete(payload, "input")
						payload["messages"] = items
					}
					raw, err := json.Marshal(payload)
					if err != nil {
						t.Fatal(err)
					}
					wire := raw
					if compressed {
						var buffer bytes.Buffer
						zip := gzip.NewWriter(&buffer)
						if _, err := zip.Write(raw); err != nil {
							t.Fatal(err)
						}
						if err := zip.Close(); err != nil {
							t.Fatal(err)
						}
						wire = buffer.Bytes()
					}
					request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(wire))
					request.Header.Set("Authorization", "Bearer "+credential)
					request.Header.Set("Content-Type", "application/json")
					if compressed {
						request.Header.Set("Content-Encoding", "gzip")
					}
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, request)
					wantStatus := http.StatusOK
					if scenario == "block_value" || scenario == "block_key" || scenario == "unsafe_mask" {
						wantStatus = http.StatusForbidden
					}
					if scenario == "attachment" || scenario == "upstream_422" {
						wantStatus = http.StatusUnprocessableEntity
					}
					if response.Code != wantStatus {
						t.Fatalf("HTTP %d，期望 %d: %s", response.Code, wantStatus, response.Body.String())
					}
					localRejection := wantStatus != http.StatusOK && scenario != "upstream_422"
					if localRejection {
						if len(forwarded) != 0 || len(auditor.events) != 1 {
							t.Fatal("本地拒绝不应调用上游，且必须有审计")
						}
						if scenario != "attachment" && (auditor.events[0].Result != "blocked" || !bytes.Equal(auditor.events[0].RequestBody, raw)) {
							t.Fatal("元数据阻断审计未保留原文")
						}
					} else {
						if len(forwarded) != 1 {
							t.Fatal("未调用上游")
						}
						body := <-forwarded
						if scenario == "mask" {
							var actual any
							if err := json.Unmarshal(body, &actual); err != nil {
								t.Fatal(err)
							}
							items[16].(map[string]any)["content"] = "probe_safe_93"
							if !reflect.DeepEqual(actual, payload) {
								t.Fatal("应只替换正文，保留所有扩展字段")
							}
						} else if !bytes.Equal(raw, body) {
							t.Fatal("无替换请求必须逐字节保留")
						}
						if wantStatus == http.StatusOK && response.Body.String() != sse {
							t.Fatal("SSE 未完整转发")
						}
					}
					snapshot := logs.Snapshot()
					if len(snapshot.Items) != 1 || !snapshot.Items[0].Finished || snapshot.Items[0].Status != wantStatus {
						t.Fatal("实时日志未记录准确结果")
					}
					if localRejection && snapshot.Items[0].UpstreamStatus != 0 {
						t.Fatal("本地拒绝误记为上游失败")
					}
					if scenario == "upstream_422" && (snapshot.Items[0].UpstreamStatus != 422 || snapshot.Items[0].ErrorCode != "upstream_http_error" || response.Body.String() != `{"error":"probe_upstream_validation_93"}`) {
						t.Fatal("上游结构错误应原样返回并与本地 422 区分")
					}
				})
			}
		}
	}
}
