package gateway

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestBothProtocolsMaskBeforeBlocking(t *testing.T) {
	for _, path := range []string{responsesPath, chatCompletionsPath} {
		for _, compressed := range []bool{false, true} {
			for _, scenario := range []string{"safe", "remaining", "target", "protocol"} {
				t.Run(path+"/"+scenario+map[bool]string{true: "/gzip", false: "/json"}[compressed], func(t *testing.T) {
					input, model, target := "stage_source_7f3", "test-model", "stage_safe_7f3"
					switch scenario {
					case "remaining":
						input += " stage_denied_7f3"
					case "target":
						target = "stage_denied_7f3"
					case "protocol":
						model = "stage_source_7f3"
					}
					calls := 0
					const sse = "data: {\"result\":\"ok\"}\n\ndata: [DONE]\n\n"
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls++
						var reader io.Reader = r.Body
						if compressed {
							unzip, err := gzip.NewReader(r.Body)
							if err != nil {
								t.Error(err)
								return
							}
							defer unzip.Close()
							reader = unzip
						}
						body, err := io.ReadAll(reader)
						if err != nil || strings.Contains(string(body), "stage_source_7f3") || !strings.Contains(string(body), "stage_safe_7f3") || r.URL.Path != path {
							t.Errorf("上游正文或路径错误: body=%s path=%s err=%v", body, r.URL.Path, err)
						}
						if r.Header.Get("Content-MD5") != "" {
							t.Error("替换后未移除原正文校验头")
						}
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = io.WriteString(w, sse)
					}))
					defer upstream.Close()
					auditor := &memoryAuditor{failAfter: -1}
					handler := newTestHandler(t, upstream.URL+"/v1", auditor, []storage.Rule{
						{ID: "block", Name: "测试拦截", Type: "keyword", Enabled: true, Action: "block", Keywords: []string{"stage_source_7f3", "stage_denied_7f3"}},
						{ID: "mask", Name: "测试替换", Type: "keyword_mapping", Enabled: true, Action: "mask", Mappings: []storage.Mapping{{Source: "stage_source_7f3", Target: target}}},
					})
					logs := &RequestLog{}
					logs.SetEnabled(true)
					handler.requestLog = logs
					payload := map[string]any{"model": model, "stream": true}
					if path == responsesPath {
						payload["input"] = input
					} else {
						payload["messages"] = []map[string]string{{"role": "user", "content": input}}
					}
					raw, _ := json.Marshal(payload)
					body := raw
					if compressed {
						var buffer bytes.Buffer
						zip := gzip.NewWriter(&buffer)
						_, _ = zip.Write(raw)
						_ = zip.Close()
						body = buffer.Bytes()
					}
					r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
					r.Header.Set("Authorization", "Bearer "+testLocalToken)
					r.Header.Set("Content-Type", "application/json")
					r.Header.Set("Content-MD5", "original-checksum")
					if compressed {
						r.Header.Set("Content-Encoding", "gzip")
					}
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, r)
					item := logs.Snapshot().Items[0]
					if scenario == "safe" {
						if response.Code != 200 || response.Body.String() != sse || calls != 1 || len(auditor.events) != 2 {
							t.Fatalf("替换后未正常转发: status=%d calls=%d events=%+v", response.Code, calls, auditor.events)
						}
						if item.Action != "mask" || item.Phase != "completed" || len(item.RuleNames) != 1 || item.RuleNames[0] != "测试替换" {
							t.Fatalf("实时日志误报拦截: %+v", item)
						}
					} else if response.Code != 403 || calls != 0 || len(auditor.events) != 1 || item.Phase != "blocked" {
						t.Fatalf("替换后仍违禁却被转发: status=%d calls=%d events=%+v log=%+v", response.Code, calls, auditor.events, item)
					}
					decision := auditor.events[0]
					if len(decision.Matches) == 0 || decision.Matches[0].RuleName != "测试替换" || decision.Matches[0].MatchedKeyword != "stage_source_7f3" {
						t.Fatalf("审计未保留替换命中: %+v", decision)
					}
					if scenario == "safe" {
						if len(decision.Matches) != 1 || len(decision.RequestBody) != 0 || decision.Action != "mask" {
							t.Fatalf("已替换的原词仍记录为拦截: %+v", decision)
						}
					} else {
						var audited map[string]any
						if err := json.Unmarshal(decision.RequestBody, &audited); err != nil {
							t.Fatal(err)
						}
						if audited["model"] != model || (path == responsesPath && audited["input"] != input) || (path == chatCompletionsPath && audited["messages"].([]any)[0].(map[string]any)["content"] != input) {
							t.Fatal("阻断审计没有保存原始请求")
						}
						if scenario != "protocol" && (len(decision.Matches) != 2 || decision.Matches[1].RuleName != "测试拦截" || decision.Matches[1].MatchedKeyword != "stage_denied_7f3") {
							t.Fatalf("阻断命中未使用替换后的文本: %+v", decision)
						}
					}
				})
			}
		}
	}
}
