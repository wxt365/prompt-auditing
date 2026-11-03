package gateway

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/config"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestModelsAliasesForwardFixedBaseWithBothAuthModes(t *testing.T) {
	const body = `{"object":"list","data":[{"id":"gpt-test","object":"model","future_field":"客户A"}]}`
	for _, base := range []string{"", "/v1", "/v1/", "/custom/api", "/custom/v1/"} {
		for _, path := range []string{modelsPath, modelsAliasPath} {
			for _, clientAuth := range []bool{false, true} {
				t.Run(base+path+map[bool]string{false: "网关认证", true: "客户端认证"}[clientAuth], func(t *testing.T) {
					auditor := &memoryAuditor{failAfter: -1}
					var calls atomic.Int32
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						if r.Method != "GET" || r.URL.Path != strings.TrimRight(base, "/")+"/models" || r.URL.RawQuery != "" {
							t.Errorf("上游方法或路径错误: %s %s", r.Method, r.URL)
						}
						wantAuth := "Bearer upstream-key"
						if clientAuth {
							wantAuth = "bearer client-private-key"
						}
						if r.Header.Get("Authorization") != wantAuth || r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Hop") != "" {
							t.Error("认证转发或逐跳 Header 过滤错误")
						}
						data, err := io.ReadAll(r.Body)
						if err != nil || len(data) != 0 {
							t.Error("模型列表转发了正文", err)
						}
						w.Header().Set("Content-Type", "application/json")
						_, _ = io.WriteString(w, body)
					}))
					defer upstream.Close()
					rules := []storage.Rule{{ID: "block", Type: "keyword", Action: "block", Enabled: true, Keywords: []string{"客户A", "gpt"}}}
					handler := newTestHandler(t, upstream.URL+base, auditor, rules)
					token := "Bearer " + testLocalToken
					if clientAuth {
						handler = newClientAuthHandler(t, upstream.URL+base, auditor, rules)
						token = "bearer client-private-key"
					}
					logs := &RequestLog{}
					logs.SetEnabled(true)
					handler.requestLog = logs
					request := httptest.NewRequest("GET", path, nil)
					request.Header.Set("Authorization", token)
					request.Header.Set("Proxy-Authorization", "private-proxy-key")
					request.Header.Set("X-Forwarded-For", "private-address")
					request.Header.Set("Connection", "X-Hop")
					request.Header.Set("X-Hop", "private-hop")
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, request)
					if response.Code != 200 || response.Body.String() != body || calls.Load() != 1 || request.URL.Path != path {
						t.Fatalf("模型列表未原样转发或改变了入站请求: status=%d calls=%d body=%s", response.Code, calls.Load(), response.Body.String())
					}
					if len(auditor.events) != 2 || auditor.events[0].RequestMethod != "GET" || auditor.events[0].RequestPath != path || auditor.events[0].Action != "allow" || auditor.events[0].Result != "forwarding" || auditor.events[1].Result != "completed" || *auditor.events[1].UpstreamStatus != 200 {
						t.Fatalf("模型发现审计错误: %+v", auditor.events)
					}
					entry := logs.Snapshot().Items[0]
					if entry.Path != path || entry.Method != "GET" || entry.Status != 200 || entry.UpstreamStatus != 200 || entry.Action != "allow" || !entry.Finished {
						t.Fatalf("模型发现实时日志错误: %+v", entry)
					}
					serialized, _ := json.Marshal(auditor.events)
					for _, secret := range []string{testLocalToken, "upstream-key", "client-private-key", "private-proxy-key", body} {
						if bytes.Contains(serialized, []byte(secret)) {
							t.Fatal("模型发现审计泄露凭证或响应正文")
						}
					}
				})
			}
		}
	}
}

func TestModelsRejectInvalidRequestsAndAuditFailuresWithoutUpstreamCalls(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	for _, test := range []struct {
		name, method, path, body string
		status                   int
		mutate                   func(*Handler, *http.Request, *memoryAuditor)
	}{
		{name: "无认证", status: 401, mutate: func(_ *Handler, r *http.Request, _ *memoryAuditor) { r.Header.Del("Authorization") }},
		{name: "POST", method: "POST", status: 405},
		{name: "HEAD", method: "HEAD", status: 405},
		{name: "模型详情仍拒绝", path: "/v1/models/gpt-test", status: 404},
		{name: "未知版本", path: "/v2/models", status: 404},
		{name: "尾部斜杠", path: "/v1/models/", status: 404},
		{name: "查询参数", path: "/v1/models?api_key=private-query-key", status: 404},
		{name: "GET携带正文", body: `{"input":"private-prompt"}`, status: 400},
		{name: "分块上传", status: 400, mutate: func(_ *Handler, r *http.Request, _ *memoryAuditor) {
			r.TransferEncoding = []string{"chunked"}
			r.ContentLength = -1
		}},
		{name: "压缩正文", status: 400, mutate: func(_ *Handler, r *http.Request, _ *memoryAuditor) { r.Header.Set("Content-Encoding", "gzip") }},
		{name: "协议升级", status: 400, mutate: func(_ *Handler, r *http.Request, _ *memoryAuditor) { r.Header.Set("Upgrade", "websocket") }},
		{name: "审计不可用", status: 503, mutate: func(_ *Handler, _ *http.Request, a *memoryAuditor) { a.unhealthy = true }},
		{name: "审计写入失败", status: 503, mutate: func(_ *Handler, _ *http.Request, a *memoryAuditor) { a.failAfter = 0 }},
		{name: "并发超限", status: 429, mutate: func(h *Handler, _ *http.Request, _ *memoryAuditor) { h.semaphore <- struct{}{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			auditor := &memoryAuditor{failAfter: -1}
			handler := newTestHandlerWithLimits(t, upstream.URL+"/v1", auditor, nil, config.LimitsConfig{MaxCompressedBytes: 1024, MaxDecompressedBytes: 1024, MaxConcurrent: 1})
			method, path := test.method, test.path
			if method == "" {
				method = "GET"
			}
			if path == "" {
				path = modelsAliasPath
			}
			r := httptest.NewRequest(method, path, strings.NewReader(test.body))
			r.Header.Set("Authorization", "Bearer "+testLocalToken)
			if test.mutate != nil {
				test.mutate(handler, r, auditor)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, r)
			if response.Code != test.status || calls.Load() != 0 {
				t.Fatalf("拒绝失败: status=%d calls=%d body=%s", response.Code, calls.Load(), response.Body.String())
			}
			if test.name == "审计写入失败" && auditor.Healthy() {
				t.Fatal("审计写入失败未标记不可用")
			}
		})
	}
}

func TestModelsPreserveUpstreamErrorsGzipAndRejectRedirects(t *testing.T) {
	for _, status := range []int{200, 302, 401, 404, 429, 500} {
		for _, compressed := range []bool{false, true} {
			t.Run(http.StatusText(status)+map[bool]string{false: "普通", true: "gzip"}[compressed], func(t *testing.T) {
				auditor := &memoryAuditor{failAfter: -1}
				body := `{"object":"list","data":[{"id":"gpt-test"}]}`
				if status >= 400 {
					body = `{"error":{"message":"denied upstream-key"}}`
				}
				var calls atomic.Int32
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Location", "/redirect-target")
					if compressed {
						w.Header().Set("Content-Encoding", "gzip")
					}
					w.WriteHeader(status)
					if compressed {
						gz := gzip.NewWriter(w)
						_, _ = io.WriteString(gz, body)
						_ = gz.Close()
					} else {
						_, _ = io.WriteString(w, body)
					}
				}))
				defer upstream.Close()
				handler := newTestHandler(t, upstream.URL+"/v1", auditor, nil)
				request := httptest.NewRequest("GET", modelsAliasPath, nil)
				request.Header.Set("Authorization", "Bearer "+testLocalToken)
				request.Header.Set("Accept-Encoding", "gzip")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != status || calls.Load() != 1 {
					t.Fatalf("上游状态或调用次数错误: %d %d", response.Code, calls.Load())
				}
				data := response.Body.Bytes()
				if response.Header().Get("Content-Encoding") == "gzip" {
					reader, err := gzip.NewReader(bytes.NewReader(data))
					if err != nil {
						t.Fatal(err)
					}
					defer reader.Close()
					data, err = io.ReadAll(reader)
					if err != nil {
						t.Fatal(err)
					}
				}
				want := body
				if status >= 400 {
					want = strings.ReplaceAll(body, "upstream-key", redactedCredential)
				}
				if string(data) != want {
					t.Fatalf("响应不正确: %s", data)
				}
				if status == 302 && response.Header().Get("Location") != "" {
					t.Fatal("重定向地址未移除")
				}
				if len(auditor.events) != 2 || auditor.events[1].UpstreamStatus == nil || *auditor.events[1].UpstreamStatus != status {
					t.Fatal("上游状态未审计")
				}
				if status >= 400 && auditor.events[1].ErrorCode != "upstream_http_error" {
					t.Fatal("上游拒绝未标记为错误")
				}
			})
		}
	}
}

func TestModelsClientCancellationStopsUpstream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		<-r.Context().Done()
	}))
	defer upstream.Close()
	auditor := &memoryAuditor{failAfter: -1}
	handler := newTestHandler(t, upstream.URL+"/v1", auditor, nil)
	r := httptest.NewRequest("GET", modelsAliasPath, nil).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+testLocalToken)
	handler.ServeHTTP(httptest.NewRecorder(), r)
	if len(auditor.events) != 2 || auditor.events[1].ErrorCode != "client_canceled" {
		t.Fatalf("取消未传递到上游: %+v", auditor.events)
	}
}
