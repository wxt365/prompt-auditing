package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestResponseRetrievalAliasesAndQuery(t *testing.T) {
	for _, base := range []string{"", "/v1/", "/proxy/v1/"} {
		for _, path := range []string{"/v1/responses/resp_test", "/responses/resp_test"} {
			t.Run(base+path, func(t *testing.T) {
				const query = "stream=true&starting_after=3&include%5B%5D=message.output_text.logprobs&include_obfuscation=false"
				const responseBody = "event: response.completed\ndata: {}\n\n"
				calls := 0
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					prefix := strings.TrimSuffix(base, "/")
					if !strings.HasSuffix(prefix, "/v1") {
						prefix += "/v1"
					}
					body, _ := io.ReadAll(r.Body)
					if r.Method != "GET" || r.URL.Path != prefix+"/responses/resp_test" || r.URL.RawQuery != query || len(body) != 0 || r.Header.Get("Authorization") != "Bearer upstream-key" {
						t.Errorf("响应查询转发错误: %s %s body=%s", r.Method, r.URL, body)
					}
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, responseBody)
				}))
				defer upstream.Close()
				auditor := &memoryAuditor{failAfter: -1}
				h := newTestHandler(t, upstream.URL+base, auditor, nil)
				h.requestLog = &RequestLog{}
				h.requestLog.SetEnabled(true)
				r := httptest.NewRequest("GET", path+"?"+query, nil)
				r.Header.Set("Authorization", "Bearer "+testLocalToken)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != 200 || w.Body.String() != responseBody || calls != 1 || r.URL.Path != path {
					t.Fatalf("响应查询失败: %d %s", w.Code, w.Body.String())
				}
				if len(auditor.events) != 2 || auditor.events[0].RequestPath != path || strings.Contains(auditor.events[0].RequestPath, "?") || len(auditor.events[0].RequestBody) != 0 {
					t.Fatalf("响应查询审计错误: %+v", auditor.events)
				}
				if entry := h.requestLog.Snapshot().Items[0]; entry.Path != path || !entry.Streaming || !entry.Finished {
					t.Fatalf("响应查询实时日志错误: %+v", entry)
				}
			})
		}
	}
}

func TestResponseRetrievalRejectsInvalidAndSensitiveParameters(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	for _, test := range []struct {
		path, method, body, encoding string
		status                       int
	}{
		{path: "/responses", status: 405},
		{path: "/v1/responses", status: 405},
		{path: "/responses/", status: 404},
		{path: "/responses/../models", status: 404},
		{path: "/responses/resp_test/extra", status: 404},
		{path: "/responses/resp_test", method: "POST", status: 405},
		{path: "/responses/resp_test?stream=invalid", status: 400},
		{path: "/responses/resp_test?stream=true&stream=false", status: 400},
		{path: "/responses/resp_test?starting_after=-1", status: 400},
		{path: "/responses/resp_test?starting_after=9223372036854775808", status: 400},
		{path: "/responses/resp_test?include%5B%5D=%25broken", status: 400},
		{path: "/responses/resp_test?api_key=private", status: 400},
		{path: "/responses/resp_test?stream=%zz", status: 400},
		{path: "/responses/resp_test", body: `{}`, status: 400},
		{path: "/responses/resp_test", encoding: "gzip", status: 400},
		{path: "/responses/resp_secret", status: 403},
		{path: "/responses/resp_test?include%5B%5D=secret", status: 403},
	} {
		t.Run(test.path+test.method+test.body+test.encoding, func(t *testing.T) {
			a := &memoryAuditor{failAfter: -1}
			h := newTestHandler(t, upstream.URL, a, []storage.Rule{{ID: "mask-id", Type: "keyword_mapping", Action: "mask", Enabled: true, Mappings: []storage.Mapping{{Source: "secret", Target: "safe"}}}})
			method := test.method
			if method == "" {
				method = "GET"
			}
			r := httptest.NewRequest(method, test.path, strings.NewReader(test.body))
			r.Header.Set("Authorization", "Bearer "+testLocalToken)
			r.Header.Set("Content-Encoding", test.encoding)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.status || len(a.events) != 1 {
				t.Fatalf("响应查询未按预期拒绝: %d %s events=%+v", w.Code, w.Body.String(), a.events)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("非法或敏感查询被转发")
	}
}
