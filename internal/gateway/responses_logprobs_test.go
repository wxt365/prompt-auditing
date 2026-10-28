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
	"strings"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestResponsesLogprobsHistoryForwardingAndSecurity(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		for _, scenario := range []string{"empty", "null", "populated", "mask_text", "block_text", "block_token", "mask_token", "block_alternative", "invalid"} {
			t.Run(fmt.Sprintf("gzip=%t/%s", compressed, scenario), func(t *testing.T) {
				const credential = "probe_credential_92"
				const sse = "event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n"
				forwarded := make(chan []byte, 1)
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(r.Body)
					if err != nil || r.URL.Path != responsesPath || r.Header.Get("Authorization") != "Bearer "+credential {
						t.Error("上游路径、认证或正文读取错误")
					}
					if r.Header.Get("Content-Encoding") == "gzip" {
						reader, err := gzip.NewReader(bytes.NewReader(body))
						if err != nil {
							t.Error(err)
							return
						}
						body, err = io.ReadAll(reader)
						_ = reader.Close()
						if err != nil {
							t.Error(err)
						}
					}
					forwarded <- body
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, sse)
				}))
				defer upstream.Close()
				auditor := &memoryAuditor{failAfter: -1}
				handler := newClientAuthHandler(t, upstream.URL+"/v1", auditor, []storage.Rule{
					{ID: "probe_mask_92", Type: "keyword_mapping", Action: "mask", Enabled: true, Mappings: []storage.Mapping{{Source: "probe_source_92", Target: "probe_safe_92"}}},
					{ID: "probe_block_92", Type: "keyword", Action: "block", Enabled: true, Keywords: []string{"probe_source_92", "probe_denied_92"}},
				})
				logs := &RequestLog{}
				logs.SetEnabled(true)
				handler.requestLog = logs
				text := "probe_history_92"
				var logprobs any = []any{}
				switch scenario {
				case "null":
					logprobs = nil
				case "populated", "mask_text":
					logprobs = []any{map[string]any{"token": "probe_token_92", "logprob": -0.125, "top_logprobs": []any{map[string]any{"token": "probe_alternative_92", "logprob": -2.5}}}}
					if scenario == "mask_text" {
						text = "probe_source_92"
					}
				case "block_text":
					text = "probe_denied_92"
				case "block_token", "mask_token":
					token := "probe_denied_92"
					if scenario == "mask_token" {
						token = "probe_source_92"
					}
					logprobs = []any{map[string]any{"token": token, "logprob": -1.0}}
				case "block_alternative":
					logprobs = []any{map[string]any{"token": "probe_token_92", "logprob": -1.0, "top_logprobs": []any{map[string]any{"token": "probe_denied_92", "logprob": -2.0}}}}
				case "invalid":
					logprobs = []any{map[string]any{"token": "probe_token_92", "logprob": "invalid"}}
				}
				items := make([]any, 8)
				for index := range items {
					items[index] = map[string]any{"role": "user", "content": "probe_normal_92"}
				}
				items = append(items, map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": text, "annotations": []any{}, "logprobs": logprobs}}})
				raw, _ := json.Marshal(map[string]any{"model": "probe_model_92", "stream": true, "input": items})
				wire := raw
				if compressed {
					var buffer bytes.Buffer
					writer := gzip.NewWriter(&buffer)
					_, _ = writer.Write(raw)
					_ = writer.Close()
					wire = buffer.Bytes()
				}
				request := httptest.NewRequest(http.MethodPost, responsesPath, bytes.NewReader(wire))
				request.Header.Set("Authorization", "Bearer "+credential)
				request.Header.Set("Content-Type", "application/json")
				if compressed {
					request.Header.Set("Content-Encoding", "gzip")
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				wantStatus := http.StatusOK
				if strings.HasPrefix(scenario, "block_") || scenario == "mask_token" {
					wantStatus = http.StatusForbidden
				} else if scenario == "invalid" {
					wantStatus = http.StatusUnprocessableEntity
				}
				if response.Code != wantStatus {
					t.Fatalf("载荷兼容或内容规则处理错误: status=%d body=%s", response.Code, response.Body.String())
				}
				if wantStatus != http.StatusOK {
					if len(forwarded) != 0 || len(auditor.events) != 1 {
						t.Fatal("拒绝请求不应到达上游，且应记录审计")
					}
					if scenario == "invalid" {
						if auditor.events[0].ErrorCode != "unsupported_payload" || !strings.Contains(response.Body.String(), "/input/8/content/0/logprobs/0") {
							t.Fatal("已知字段类型错误应继续 422，并给出准确字段路径")
						}
					} else if auditor.events[0].Result != "blocked" || !bytes.Equal(auditor.events[0].RequestBody, raw) {
						t.Fatal("规则阻断审计未保留原始历史载荷")
					}
					return
				}
				if response.Body.String() != sse || len(forwarded) != 1 || len(auditor.events) != 2 || auditor.events[1].Result != "completed" {
					t.Fatal("历史请求未完整转发、返回 SSE 或记录完成结果")
				}
				body := <-forwarded
				if scenario != "mask_text" && !bytes.Equal(body, raw) {
					t.Fatal("未替换的请求正文应原样转发")
				}
				if scenario == "mask_text" {
					var result struct {
						Input []json.RawMessage
					}
					var history struct{ Content []map[string]any }
					if json.Unmarshal(body, &result) != nil || len(result.Input) != 9 || json.Unmarshal(result.Input[8], &history) != nil || len(history.Content) != 1 || history.Content[0]["text"] != "probe_safe_92" || !reflect.DeepEqual(history.Content[0]["logprobs"], logprobs) || auditor.events[0].Action != "mask" {
						t.Fatal("正文替换应放行，且不能改写概率元数据")
					}
				}
				if snapshot := logs.Snapshot(); len(snapshot.Items) != 1 || snapshot.Items[0].ErrorCode != "" || snapshot.Items[0].Phase != "completed" {
					t.Fatal("兼容请求应在实时日志中正常完成")
				}
			})
		}
	}
}
