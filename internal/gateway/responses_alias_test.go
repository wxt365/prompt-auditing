package gateway

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestResponsesAliasesShareRoutingInspectionAndLogs(t *testing.T) {
	for _, target := range []struct{ base, path string }{
		{"", "/v1/responses"},
		{"/v1", "/v1/responses"},
		{"/v1/", "/v1/responses"},
		{"/proxy/v1/", "/proxy/v1/responses"},
		{"/proxy/", "/proxy/v1/responses"},
	} {
		for _, path := range []string{responsesPath, responsesAliasPath} {
			for _, encoding := range []string{"", "gzip"} {
				t.Run(target.base+path+"/"+encoding, func(t *testing.T) {
					received := make(chan []byte, 1)
					const normal = `{"output_text":"OK"}`
					const sse = "event: response.completed\ndata: {}\n\n"
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.Method != http.MethodPost || r.URL.Path != target.path || r.Header.Get("Authorization") != "Bearer upstream-key" || r.Header.Get("Content-Encoding") != encoding {
							t.Errorf("上游方法、路径、认证或编码错误: %s %s", r.Method, r.URL.Path)
						}
						wire, err := io.ReadAll(r.Body)
						if err != nil {
							t.Error(err)
						}
						received <- wire
						body := wire
						if encoding == "gzip" {
							reader, err := gzip.NewReader(bytes.NewReader(wire))
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
						var object map[string]any
						if err := json.Unmarshal(body, &object); err != nil || object["model"] != "gpt-test" || strings.Contains(string(body), "内部系统A") {
							t.Errorf("Responses 正文脱敏或协议保留失败: %s", body)
						}
						if object["stream"] == true {
							if object["input"] != "业务系统" {
								t.Error("Responses 别名未执行文本脱敏")
							}
							w.Header().Set("Content-Type", "text/event-stream")
							_, _ = io.WriteString(w, sse)
						} else {
							w.Header().Set("Content-Type", "application/json")
							_, _ = io.WriteString(w, normal)
						}
					}))
					defer upstream.Close()
					auditor := &memoryAuditor{failAfter: -1}
					handler := newTestHandler(t, upstream.URL+target.base, auditor, []storage.Rule{
						{ID: "block", Type: "keyword", Action: "block", Enabled: true, Keywords: []string{"客户A"}},
						{ID: "mask", Type: "keyword_mapping", Action: "mask", Enabled: true, Mappings: []storage.Mapping{{Source: "内部系统A", Target: "业务系统"}}},
						{ID: "warn", Type: "keyword", Action: "warn", Enabled: true, Keywords: []string{"提醒"}},
					})
					handler.requestLog = &RequestLog{}
					handler.requestLog.SetEnabled(true)
					for _, test := range []struct {
						input, action string
						stream        bool
					}{
						{"客户A", "block", false}, {"内部系统A", "mask", true}, {"正常", "allow", false}, {"提醒", "warn", false},
					} {
						body := []byte(fmt.Sprintf(`{ "model":"gpt-test", "input":%q, "stream":%t }`, test.input, test.stream))
						wire := body
						if encoding == "gzip" {
							wire = gzipBody(t, body)
						}
						request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(wire))
						request.Header.Set("Authorization", "Bearer "+testLocalToken)
						request.Header.Set("Content-Type", "application/json")
						if encoding != "" {
							request.Header.Set("Content-Encoding", encoding)
						}
						before := len(auditor.events)
						response := httptest.NewRecorder()
						handler.ServeHTTP(response, request)
						if request.URL.Path != path || len(auditor.events) <= before || auditor.events[before].Action != test.action {
							t.Fatalf("调用者请求被修改或审计错误: %s %+v", request.URL.Path, auditor.events[before:])
						}
						if test.action == "block" {
							if response.Code != http.StatusForbidden || len(received) != 0 {
								t.Fatal("Responses 阻断失败")
							}
							continue
						}
						want := normal
						if test.stream {
							want = sse
						}
						if response.Code != http.StatusOK || response.Body.String() != want || len(received) != 1 {
							t.Fatalf("Responses JSON/SSE 转发失败: %d %s", response.Code, response.Body.String())
						}
						forwarded := <-received
						if test.action != "mask" && !bytes.Equal(forwarded, wire) {
							t.Fatal("未脱敏的请求未保留原始字节")
						}
					}
					for _, entry := range handler.requestLog.Snapshot().Items {
						if entry.Path != path || !entry.Finished {
							t.Fatalf("Responses 日志未保留原路径: %+v", entry)
						}
					}
				})
			}
		}
	}
}
