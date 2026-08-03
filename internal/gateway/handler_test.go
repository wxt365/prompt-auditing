package gateway

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/audit"
	"github.com/xiaotaowang/prompt-auditing/internal/config"
	"github.com/xiaotaowang/prompt-auditing/internal/security"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

const testLocalToken = "local-token-with-at-least-32-bytes"

type memoryAuditor struct {
	mu        sync.Mutex
	events    []audit.Event
	failAfter int
	unhealthy bool
}

func (a *memoryAuditor) Write(event audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failAfter == 0 {
		return io.ErrClosedPipe
	}
	if a.failAfter > 0 {
		a.failAfter--
	}
	a.events = append(a.events, event)
	return nil
}

func (a *memoryAuditor) Fingerprint([]byte) string { return "fingerprint" }
func (a *memoryAuditor) Healthy() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.unhealthy
}
func (a *memoryAuditor) MarkUnhealthy() {
	a.mu.Lock()
	a.unhealthy = true
	a.mu.Unlock()
}

func TestBlockDoesNotCallUpstreamAndAuditsRequest(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalls.Add(1)
	}))
	defer upstream.Close()
	auditor := &memoryAuditor{failAfter: -1}
	handler := newTestHandler(t, upstream.URL, auditor, []storage.Rule{{
		ID: "block-customer", Type: "keyword", Enabled: true, Action: security.ActionBlock, Keywords: []string{"客户A"},
	}})

	response := performRequest(handler, []byte(`{"model":"gpt-test","input":"客户A"}`), "")
	if response.Code != http.StatusForbidden {
		t.Fatalf("状态码 = %d，正文 = %s", response.Code, response.Body.String())
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("阻断请求调用上游 %d 次", upstreamCalls.Load())
	}
	if len(auditor.events) != 1 {
		t.Fatalf("阻断审计错误: %#v", auditor.events)
	}
	var auditedBody map[string]any
	if err := json.Unmarshal(auditor.events[0].RequestBody, &auditedBody); err != nil ||
		auditedBody["model"] != "gpt-test" || auditedBody["input"] != "客户A" {
		t.Fatalf("阻断审计正文错误: %s err=%v", auditor.events[0].RequestBody, err)
	}
	if strings.Contains(response.Body.String(), "客户A") || strings.Contains(response.Body.String(), "block-customer") {
		t.Fatalf("阻断响应泄露命中详情: %s", response.Body.String())
	}
}

func TestBlockAuditRedactsConfiguredCredentials(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("阻断请求不应调用上游")
	}))
	defer upstream.Close()
	auditor := &memoryAuditor{failAfter: -1}
	handler := newTestHandler(t, upstream.URL, auditor, []storage.Rule{{
		ID: "block-secret", Type: "keyword", Enabled: true, Action: security.ActionBlock,
		Keywords: []string{"upstream-key", testLocalToken},
	}})
	body := `{"model":"gpt-test","input":"upstream-key ` + testLocalToken + `"}`
	response := performRequest(handler, []byte(body), "")
	if response.Code != http.StatusForbidden || len(auditor.events) != 1 {
		t.Fatalf("凭证阻断失败: status=%d events=%#v", response.Code, auditor.events)
	}
	event := auditor.events[0]
	serialized, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(serialized, []byte("upstream-key")) || bytes.Contains(serialized, []byte(testLocalToken)) ||
		!bytes.Contains(serialized, []byte(redactedCredential)) || event.MatchCount != 2 || len(event.Matches) != 2 ||
		strings.Contains(event.Matches[0].MatchedKeyword, "upstream-key") ||
		strings.Contains(event.Matches[1].MatchedKeyword, testLocalToken) {
		t.Fatalf("阻断审计凭证脱敏错误: %s", serialized)
	}
}

func TestNewHandlerRejectsSharedLocalAndUpstreamSecret(t *testing.T) {
	parsed, err := url.Parse("https://example.invalid/v1")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := security.NewEngine(storage.RuleSet{Version: "1", DefaultAction: storage.DefaultAction})
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewHandler(Options{
		Upstream: parsed, Client: upstreamClient(), Engine: engine, Audit: &memoryAuditor{failAfter: -1},
		LocalToken: testLocalToken, UpstreamKey: testLocalToken,
		Limits: config.LimitsConfig{MaxCompressedBytes: 1 << 20, MaxDecompressedBytes: 1 << 20, MaxConcurrent: 10},
	})
	if err == nil {
		t.Fatal("本地令牌与上游 API Key 相同时必须拒绝启动")
	}
}

func TestToolOutputBlockDoesNotCallUpstream(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalls.Add(1)
	}))
	defer upstream.Close()
	handler := newTestHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, []storage.Rule{{
		ID: "block-customer", Type: "keyword", Enabled: true, Action: security.ActionBlock, Keywords: []string{"客户A"},
	}})

	response := performRequest(handler, []byte(`{"model":"gpt-test","input":[{"type":"function_call_output","call_id":"call_1","output":"客户A"}]}`), "")
	if response.Code != http.StatusForbidden || upstreamCalls.Load() != 0 {
		t.Fatalf("工具输出阻断失败: status=%d calls=%d body=%s", response.Code, upstreamCalls.Load(), response.Body.String())
	}
}

func TestWarnAuditsAndForwardsOriginalRequest(t *testing.T) {
	received := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		received <- string(body)
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	auditor := &memoryAuditor{failAfter: -1}
	handler := newTestHandler(t, upstream.URL, auditor, []storage.Rule{{
		ID: "warn-private", Type: "keyword", Enabled: true, Action: security.ActionWarn, Keywords: []string{"10.1.2.3"},
	}})
	body := `{"model":"gpt-test","input":"访问 10.1.2.3"}`
	response := performRequest(handler, []byte(body), "")
	if response.Code != http.StatusOK || <-received != body {
		t.Fatalf("warn 未原样转发: status=%d body=%s", response.Code, response.Body.String())
	}
	if len(auditor.events) != 2 || auditor.events[0].Action != security.ActionWarn ||
		auditor.events[0].Result != "forwarding" || len(auditor.events[0].RequestBody) != 0 ||
		auditor.events[1].EventType != "completion" {
		t.Fatalf("warn 审计错误: %#v", auditor.events)
	}
}

func TestBlockAuditContainsAllRuleIDsInOccurrenceOrder(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("阻断请求不应调用上游")
	}))
	defer upstream.Close()
	auditor := &memoryAuditor{failAfter: -1}
	handler := newTestHandler(t, upstream.URL, auditor, []storage.Rule{
		{ID: "rule.project", Type: "keyword", Enabled: true, Action: security.ActionBlock, Keywords: []string{"项目B"}},
		{ID: "rule.customer", Type: "keyword", Enabled: true, Action: security.ActionBlock, Keywords: []string{"客户A"}},
	})
	response := performRequest(handler, []byte(`{"model":"gpt-test","input":"客户A 项目B 客户A"}`), "")
	if response.Code != http.StatusForbidden || len(auditor.events) != 1 {
		t.Fatalf("多规则阻断失败: status=%d events=%#v", response.Code, auditor.events)
	}
	event := auditor.events[0]
	if strings.Join(event.RuleIDs, ",") != "rule.customer,rule.project" ||
		strings.Join(event.MatchedKeywords, ",") != "客户A,项目B" || event.MatchCount != 3 {
		t.Fatalf("多规则审计错误: %#v", event)
	}
}

func TestMaskReplacesAuthorizationAndPreservesGzip(t *testing.T) {
	type receivedRequest struct {
		Authorization string
		Encoding      string
		Body          string
		Host          string
		ConnectionTag string
		Forwarded     string
		ForwardedHost string
		Integrity     []string
	}
	received := make(chan receivedRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		bodyReader := io.Reader(request.Body)
		if request.Header.Get("Content-Encoding") == "gzip" {
			reader, err := gzip.NewReader(request.Body)
			if err != nil {
				t.Error(err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			defer reader.Close()
			bodyReader = reader
		}
		body, _ := io.ReadAll(bodyReader)
		received <- receivedRequest{
			Authorization: request.Header.Get("Authorization"), Encoding: request.Header.Get("Content-Encoding"),
			Body: string(body), Host: request.Host, ConnectionTag: request.Header.Get("X-Remove-Me"),
			Forwarded: request.Header.Get("Forwarded"), ForwardedHost: request.Header.Get("X-Forwarded-Host"),
			Integrity: []string{request.Header.Get("Content-MD5"), request.Header.Get("Digest"), request.Header.Get("Etag"),
				request.Header.Get("Content-Digest"), request.Header.Get("Repr-Digest")},
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	handler := newTestHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, []storage.Rule{{
		ID: "mask-system", Type: "keyword_mapping", Enabled: true, Action: security.ActionMask,
		Mappings: []storage.Mapping{{Source: "内部系统A", Target: "业务系统"}},
	}})
	raw := []byte(`{"model":"gpt-test","input":"内部系统A"}`)
	compressed := gzipBody(t, raw)
	request := httptest.NewRequest(http.MethodPost, responsesPath, bytes.NewReader(compressed))
	request.Header.Set("Authorization", "Bearer "+testLocalToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Content-Encoding", "gzip")
	request.Header.Set("Connection", "X-Remove-Me")
	request.Header.Set("X-Remove-Me", "secret-hop")
	request.Header.Set("Forwarded", "host=attacker.invalid")
	request.Header.Set("X-Forwarded-Host", "attacker.invalid")
	request.Header.Set("Content-MD5", "stale-md5")
	request.Header.Set("Digest", "sha-256=stale")
	request.Header.Set("Etag", `"stale"`)
	request.Header.Set("Content-Digest", "sha-256=:stale:")
	request.Header.Set("Repr-Digest", "sha-256=:stale:")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Body.String() != `{"ok":true}` {
		t.Fatalf("代理响应错误: %d %s", response.Code, response.Body.String())
	}
	got := <-received
	if got.Authorization != "Bearer upstream-key" || got.Encoding != "gzip" {
		t.Fatalf("上游 Header 错误: %#v", got)
	}
	if strings.Contains(got.Body, "内部系统A") || !strings.Contains(got.Body, "业务系统") {
		t.Fatalf("上游未收到脱敏正文: %s", got.Body)
	}
	if got.ConnectionTag != "" || got.Forwarded != "" || got.ForwardedHost != "" {
		t.Fatalf("连接或路由 Header 被转发: %#v", got)
	}
	for index, value := range got.Integrity {
		if value != "" {
			t.Fatalf("脱敏后仍转发第 %d 个正文完整性 Header: %#v", index, got)
		}
	}
}

func TestValidationOrderAndStableErrorCodes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("校验失败请求不应调用上游")
	}))
	defer upstream.Close()
	tests := []struct {
		name        string
		method      string
		path        string
		token       string
		contentType string
		encoding    string
		body        string
		status      int
		code        string
	}{
		{name: "认证优先于路径", method: http.MethodGet, path: "/unknown", token: "bad", status: 401, code: "gateway_unauthorized"},
		{name: "路径优先于方法", method: http.MethodGet, path: "/unknown", token: testLocalToken, status: 404, code: "gateway_route_not_supported"},
		{name: "方法", method: http.MethodGet, path: responsesPath, token: testLocalToken, status: 405, code: "gateway_route_not_supported"},
		{name: "编码优先于类型", method: http.MethodPost, path: responsesPath, token: testLocalToken, contentType: "text/plain", encoding: "br", body: "x", status: 415, code: "unsupported_media_type"},
		{name: "类型", method: http.MethodPost, path: responsesPath, token: testLocalToken, contentType: "text/plain", body: `{}`, status: 415, code: "unsupported_media_type"},
		{name: "JSON", method: http.MethodPost, path: responsesPath, token: testLocalToken, contentType: "application/json", body: `{`, status: 422, code: "unsupported_payload"},
		{name: "附件", method: http.MethodPost, path: responsesPath, token: testLocalToken, contentType: "application/json", body: `{"input":[{"type":"input_image","image_url":"x"}]}`, status: 422, code: "unsupported_payload"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newTestHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, nil)
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer "+test.token)
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			if test.encoding != "" {
				request.Header.Set("Content-Encoding", test.encoding)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || decodeErrorCode(t, response) != test.code {
				t.Fatalf("响应 = %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestDuplicateContentHeadersAreRejected(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalls.Add(1)
	}))
	defer upstream.Close()

	tests := []struct {
		name   string
		header string
		values []string
	}{
		{name: "重复 Content-Type", header: "Content-Type", values: []string{"application/json", "text/plain"}},
		{name: "重复 Content-Encoding", header: "Content-Encoding", values: []string{"gzip", "identity"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newTestHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, nil)
			body := []byte(`{"input":"normal"}`)
			if test.header == "Content-Encoding" {
				body = gzipBody(t, body)
			}
			request := httptest.NewRequest(http.MethodPost, responsesPath, bytes.NewReader(body))
			request.Header.Set("Authorization", "Bearer "+testLocalToken)
			request.Header.Set("Content-Type", "application/json")
			for _, value := range test.values {
				request.Header.Add(test.header, value)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnsupportedMediaType || decodeErrorCode(t, response) != "unsupported_media_type" {
				t.Fatalf("响应 = %d %s", response.Code, response.Body.String())
			}
		})
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("重复内容 Header 调用上游 %d 次", upstreamCalls.Load())
	}
}

func TestProtocolUpgradeIsRejected(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalls.Add(1)
	}))
	defer upstream.Close()
	handler := newTestHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, nil)
	request := httptest.NewRequest(http.MethodPost, responsesPath, strings.NewReader(`{"model":"gpt-test","input":"normal"}`))
	request.Header.Set("Authorization", "Bearer "+testLocalToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Connection", "keep-alive, Upgrade")
	request.Header.Set("Upgrade", "websocket")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || decodeErrorCode(t, response) != "gateway_route_not_supported" {
		t.Fatalf("协议升级响应 = %d %s", response.Code, response.Body.String())
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("协议升级请求调用上游 %d 次", upstreamCalls.Load())
	}
}

func TestCompressedAndDecompressedBodyLimits(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalls.Add(1)
	}))
	defer upstream.Close()
	limits := config.LimitsConfig{MaxCompressedBytes: 128, MaxDecompressedBytes: 128, MaxConcurrent: 10}
	handler := newTestHandlerWithLimits(t, upstream.URL, &memoryAuditor{failAfter: -1}, nil, limits)

	compressedTooLarge := performRequest(handler, bytes.Repeat([]byte("x"), 129), "")
	if compressedTooLarge.Code != http.StatusRequestEntityTooLarge || decodeErrorCode(t, compressedTooLarge) != "payload_too_large" {
		t.Fatalf("压缩前超限响应 = %d %s", compressedTooLarge.Code, compressedTooLarge.Body.String())
	}
	decoded := []byte(`{"model":"gpt-test","input":"` + strings.Repeat("a", 512) + `"}`)
	compressed := gzipBody(t, decoded)
	if int64(len(compressed)) >= limits.MaxCompressedBytes {
		t.Fatalf("测试 gzip 样本过大: %d", len(compressed))
	}
	decompressedTooLarge := performRequest(handler, compressed, "gzip")
	if decompressedTooLarge.Code != http.StatusRequestEntityTooLarge || decodeErrorCode(t, decompressedTooLarge) != "payload_too_large" {
		t.Fatalf("解压后超限响应 = %d %s", decompressedTooLarge.Code, decompressedTooLarge.Body.String())
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("请求体超限后调用上游 %d 次", upstreamCalls.Load())
	}
}

func TestUpstreamStatusAndBodyAreForwardedWithoutRetry(t *testing.T) {
	for _, status := range []int{400, 401, 429, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				writer.Header().Set("Content-Type", "application/json")
				writer.Header().Set("Content-Length", "16")
				writer.WriteHeader(status)
				_, _ = writer.Write([]byte(`{"error":"test"}`))
			}))
			defer upstream.Close()
			handler := newTestHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, nil)
			response := performRequest(handler, []byte(`{"model":"gpt-test","input":"normal"}`), "")
			if response.Code != status || response.Body.String() != `{"error":"test"}` || calls.Load() != 1 {
				t.Fatalf("透传错误: status=%d body=%q calls=%d", response.Code, response.Body.String(), calls.Load())
			}
		})
	}
}

func TestUpstreamErrorRedactsConfiguredCredentials(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Content-Encoding", "gzip")
		writer.Header().Set("X-Debug-Key", "Bearer upstream-key")
		writer.WriteHeader(http.StatusUnauthorized)
		compressed := gzip.NewWriter(writer)
		_, _ = io.WriteString(compressed, `{"error":"`+testLocalToken+` \u0075\u0070\u0073\u0074\u0072\u0065\u0061\u006d\u002d\u006b\u0065\u0079"}`)
		_ = compressed.Close()
	}))
	defer upstream.Close()
	handler := newTestHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, nil)

	response := performRequest(handler, []byte(`{"model":"gpt-test","input":"normal"}`), "")
	if response.Code != http.StatusUnauthorized || response.Header().Get("Content-Encoding") != "" {
		t.Fatalf("上游错误响应 Header 未安全重建: status=%d headers=%v", response.Code, response.Header())
	}
	if response.Header().Get("X-Debug-Key") != "Bearer "+redactedCredential {
		t.Fatalf("上游错误诊断 Header 未脱敏: %v", response.Header())
	}
	body := response.Body.String()
	if strings.Contains(body, testLocalToken) || strings.Contains(body, "upstream-key") ||
		strings.Count(body, redactedCredential) != 2 {
		t.Fatalf("上游错误响应未脱敏: %q", body)
	}
	if response.Header().Get("Content-Length") != fmt.Sprint(len(response.Body.Bytes())) {
		t.Fatalf("上游错误响应长度错误: headers=%v body=%q", response.Header(), body)
	}
}

func TestUpstreamRedirectIsReturnedWithoutFollowing(t *testing.T) {
	var redirectedCalls atomic.Int32
	redirected := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectedCalls.Add(1)
	}))
	defer redirected.Close()
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		writer.Header().Set("Location", redirected.URL+"/v1/responses")
		writer.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer upstream.Close()
	handler := newTestHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, nil)

	response := performRequest(handler, []byte(`{"model":"gpt-test","input":"normal"}`), "")
	if response.Code != http.StatusTemporaryRedirect || response.Header().Get("Location") != "" ||
		upstreamCalls.Load() != 1 || redirectedCalls.Load() != 0 {
		t.Fatalf("上游重定向处理错误: status=%d location=%q upstream=%d redirected=%d",
			response.Code, response.Header().Get("Location"), upstreamCalls.Load(), redirectedCalls.Load())
	}
}

func TestUpstreamRequestBodyCannotBeReplayed(t *testing.T) {
	var replayable bool
	var integrityPreserved bool
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		replayable = request.GetBody != nil
		integrityPreserved = request.Header.Get("Content-MD5") == "original-md5" && request.Header.Get("Digest") == "sha-256=original"
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			Request:    request,
		}, nil
	})}
	parsed, err := url.Parse("https://example.invalid/v1")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := security.NewEngine(storage.RuleSet{Version: "1", DefaultAction: storage.DefaultAction})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{
		Upstream: parsed, Client: client, Engine: engine, Audit: &memoryAuditor{failAfter: -1},
		LocalToken: testLocalToken, UpstreamKey: "upstream-key", OSUser: "developer",
		Limits: config.LimitsConfig{MaxCompressedBytes: 1 << 20, MaxDecompressedBytes: 1 << 20, MaxConcurrent: 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, responsesPath, strings.NewReader(`{"model":"gpt-test","input":"normal"}`))
	request.Header.Set("Authorization", "Bearer "+testLocalToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "do-not-replay")
	request.Header.Set("Content-MD5", "original-md5")
	request.Header.Set("Digest", "sha-256=original")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || replayable || !integrityPreserved {
		t.Fatalf("允许请求转发错误: status=%d replayable=%t integrity=%t", response.Code, replayable, integrityPreserved)
	}
}

func TestNoOpMaskPreservesContentIntegrityHeaders(t *testing.T) {
	var contentMD5 string
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		contentMD5 = request.Header.Get("Content-MD5")
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Request: request,
		}, nil
	})}
	parsed, err := url.Parse("https://example.invalid/v1")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := security.NewEngine(storage.RuleSet{
		Version: "1", DefaultAction: storage.DefaultAction,
		Rules: []storage.Rule{{
			ID: "mask.same", Type: "keyword_mapping", Enabled: true, Action: security.ActionMask,
			Mappings: []storage.Mapping{{Source: "same", Target: "same"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{
		Upstream: parsed, Client: client, Engine: engine, Audit: &memoryAuditor{failAfter: -1},
		LocalToken: testLocalToken, UpstreamKey: "upstream-key", OSUser: "developer",
		Limits: config.LimitsConfig{MaxCompressedBytes: 1 << 20, MaxDecompressedBytes: 1 << 20, MaxConcurrent: 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, responsesPath, strings.NewReader(`{"input":"same"}`))
	request.Header.Set("Authorization", "Bearer "+testLocalToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Content-MD5", "original-md5")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || contentMD5 != "original-md5" {
		t.Fatalf("未变化正文的完整性 Header 被删除: status=%d content-md5=%q", response.Code, contentMD5)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestSSEBodyAndStatusAreTransparent(t *testing.T) {
	expected := "event: response.output_text.delta\ndata: {\"delta\":\"A\"}\n\nevent: response.completed\ndata: {}\n\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.Header().Set("X-Upstream", "kept")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(expected))
	}))
	defer upstream.Close()
	handler := newTestHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, nil)
	response := performRequest(handler, []byte(`{"model":"gpt-test","input":"normal","stream":true}`), "")
	if response.Code != http.StatusOK || response.Body.String() != expected || response.Header().Get("X-Upstream") != "kept" {
		t.Fatalf("SSE 透传错误: %d %q %#v", response.Code, response.Body.String(), response.Header())
	}
}

func TestSSEMidStreamFailureIsAudited(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.Header().Set("Content-Length", "1024")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("event: response.output_text.delta\ndata: {\"delta\":\"A\"}\n\n"))
	}))
	defer upstream.Close()
	auditor := &memoryAuditor{failAfter: -1}
	handler := newTestHandler(t, upstream.URL, auditor, nil)

	response := performRequest(handler, []byte(`{"model":"gpt-test","input":"normal","stream":true}`), "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "response.output_text.delta") {
		t.Fatalf("SSE 中途断流响应错误: %d %q", response.Code, response.Body.String())
	}
	if len(auditor.events) != 2 {
		t.Fatalf("SSE 中途断流审计事件数 = %d", len(auditor.events))
	}
	completion := auditor.events[1]
	if completion.EventType != "completion" || completion.Result != "upstream_stream_error" ||
		completion.ErrorCode != "upstream_error" || completion.UpstreamStatus == nil || *completion.UpstreamStatus != http.StatusOK {
		t.Fatalf("SSE 中途断流审计错误: %#v", completion)
	}
}

func TestEleventhConcurrentRequestIsRejectedWithoutQueueing(t *testing.T) {
	entered := make(chan struct{}, 10)
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	handler := newTestHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, nil)

	responses := make(chan *httptest.ResponseRecorder, 10)
	for index := 0; index < 10; index++ {
		go func() {
			responses <- performRequest(handler, []byte(`{"model":"gpt-test","input":"normal"}`), "")
		}()
	}
	for index := 0; index < 10; index++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("10 个并发请求未能全部到达上游")
		}
	}

	overflow := performRequest(handler, []byte(`{"model":"gpt-test","input":"overflow"}`), "")
	if overflow.Code != http.StatusTooManyRequests || decodeErrorCode(t, overflow) != "gateway_busy" {
		t.Fatalf("第 11 个并发请求响应 = %d %s", overflow.Code, overflow.Body.String())
	}
	close(release)
	for index := 0; index < 10; index++ {
		response := <-responses
		if response.Code != http.StatusOK {
			t.Fatalf("并发请求状态 = %d %s", response.Code, response.Body.String())
		}
	}
}

func TestUnsupportedPayloadAndAuditFailureNeverReachUpstream(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()

	handler := newTestHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, nil)
	unsupported := performRequest(handler, []byte(`{"model":"gpt-test","unknown_text":"secret"}`), "")
	if unsupported.Code != http.StatusUnprocessableEntity {
		t.Fatalf("未知文本字段状态码 = %d", unsupported.Code)
	}
	nested := performRequest(handler, []byte(`{"model":"gpt-test","input":[{"type":"message","role":"user","content":"normal","future_text":"secret"}]}`), "")
	if nested.Code != http.StatusUnprocessableEntity || decodeErrorCode(t, nested) != "unsupported_payload" {
		t.Fatalf("嵌套未知文本字段响应 = %d %s", nested.Code, nested.Body.String())
	}

	failingAudit := &memoryAuditor{failAfter: 0}
	handler = newTestHandler(t, upstream.URL, failingAudit, nil)
	failed := performRequest(handler, []byte(`{"model":"gpt-test","input":"normal"}`), "")
	if failed.Code != http.StatusServiceUnavailable || !strings.Contains(failed.Body.String(), "audit_unavailable") {
		t.Fatalf("审计失败响应 = %d %s", failed.Code, failed.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("失败关闭场景调用上游 %d 次", calls.Load())
	}
}

func TestPayloadValidationPrecedesAuditAvailability(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	auditor := &memoryAuditor{failAfter: -1, unhealthy: true}
	handler := newTestHandler(t, upstream.URL, auditor, nil)

	invalid := performRequest(handler, []byte(`{"model":"gpt-test","input":`), "")
	if invalid.Code != http.StatusUnprocessableEntity || decodeErrorCode(t, invalid) != "unsupported_payload" {
		t.Fatalf("载荷校验未优先执行: %d %s", invalid.Code, invalid.Body.String())
	}
	valid := performRequest(handler, []byte(`{"model":"gpt-test","input":"normal"}`), "")
	if valid.Code != http.StatusServiceUnavailable || decodeErrorCode(t, valid) != "audit_unavailable" {
		t.Fatalf("有效载荷未在审计不可用时失败关闭: %d %s", valid.Code, valid.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("审计不可用场景调用上游 %d 次", calls.Load())
	}
}

func TestSecurityEnginePanicFailsClosed(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalls.Add(1)
	}))
	defer upstream.Close()
	parsed, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{
		Upstream: parsed, Client: upstreamClient(), Engine: panicSecurityEngine{}, Audit: &memoryAuditor{failAfter: -1},
		LocalToken: testLocalToken, UpstreamKey: "upstream-key", OSUser: "developer",
		Limits: config.LimitsConfig{MaxCompressedBytes: 1 << 20, MaxDecompressedBytes: 1 << 20, MaxConcurrent: 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := performRequest(handler, []byte(`{"model":"gpt-test","input":"normal"}`), "")
	if response.Code != http.StatusServiceUnavailable || decodeErrorCode(t, response) != "security_engine_unavailable" {
		t.Fatalf("规则引擎异常响应 = %d %s", response.Code, response.Body.String())
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("规则引擎异常后调用上游 %d 次", upstreamCalls.Load())
	}
}

func TestSecurityInspectionLimitFailsClosedWithoutCallingUpstream(t *testing.T) {
	var upstreamCalls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		upstreamCalls.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`)), Request: request}, nil
	})}
	engine, err := security.NewEngine(storage.RuleSet{
		Version: "1", DefaultAction: storage.DefaultAction,
		Rules: []storage.Rule{{ID: "single-character", Type: "keyword", Enabled: true, Action: security.ActionBlock, Keywords: []string{"a"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{
		Upstream: parsed, Client: client, Engine: engine, Audit: &memoryAuditor{failAfter: -1},
		LocalToken: testLocalToken, UpstreamKey: "upstream-key", OSUser: "developer",
		Limits: config.LimitsConfig{MaxCompressedBytes: 1 << 20, MaxDecompressedBytes: 1 << 20, MaxConcurrent: 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{"input": strings.Repeat("a", security.MaxMatchesPerInspection+1)})
	if err != nil {
		t.Fatal(err)
	}
	response := performRequest(handler, body, "")
	if response.Code != http.StatusServiceUnavailable || decodeErrorCode(t, response) != "security_engine_unavailable" {
		t.Fatalf("命中上限响应 = %d %s", response.Code, response.Body.String())
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("命中上限后调用上游 %d 次", upstreamCalls.Load())
	}
}

func TestHandlerAddsSecurityInspectionDeadline(t *testing.T) {
	parsed, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	engine := &deadlineSecurityEngine{}
	handler, err := NewHandler(Options{
		Upstream: parsed, Client: upstreamClient(), Engine: engine, Audit: &memoryAuditor{failAfter: -1},
		LocalToken: testLocalToken, UpstreamKey: "upstream-key", OSUser: "developer",
		Limits: config.LimitsConfig{MaxCompressedBytes: 1 << 20, MaxDecompressedBytes: 1 << 20, MaxConcurrent: 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := performRequest(handler, []byte(`{"input":"normal"}`), "")
	if response.Code != http.StatusServiceUnavailable || decodeErrorCode(t, response) != "security_engine_unavailable" || !engine.sawDeadline {
		t.Fatalf("扫描超时未失败关闭: status=%d deadline=%t body=%s", response.Code, engine.sawDeadline, response.Body.String())
	}
}

type panicSecurityEngine struct{}

func (panicSecurityEngine) RuleSetVersion() string { return "1" }
func (panicSecurityEngine) Inspect(context.Context, security.Payload) (security.Decision, error) {
	panic("测试注入的规则引擎异常")
}
func (panicSecurityEngine) ApplyMask(security.Payload, security.Decision) error { return nil }

type deadlineSecurityEngine struct {
	sawDeadline bool
}

func (*deadlineSecurityEngine) RuleSetVersion() string { return "1" }
func (engine *deadlineSecurityEngine) Inspect(ctx context.Context, _ security.Payload) (security.Decision, error) {
	deadline, ok := ctx.Deadline()
	engine.sawDeadline = ok && time.Until(deadline) <= securityInspectionTimeout
	return security.Decision{}, context.DeadlineExceeded
}
func (*deadlineSecurityEngine) ApplyMask(security.Payload, security.Decision) error { return nil }

func TestHealthBecomesUnavailableAfterCompletionAuditFailure(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	auditor := &memoryAuditor{failAfter: 1}
	handler := newTestHandler(t, upstream.URL, auditor, nil)
	response := performRequest(handler, []byte(`{"model":"gpt-test","input":"normal"}`), "")
	if response.Code != http.StatusOK {
		t.Fatalf("首个请求状态 = %d", response.Code)
	}
	healthRequest := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	healthResponse := httptest.NewRecorder()
	handler.ServeHTTP(healthResponse, healthRequest)
	if healthResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("健康状态 = %d %s", healthResponse.Code, healthResponse.Body.String())
	}
}

func TestHealthResponseContainsOnlyDocumentedStatusFields(t *testing.T) {
	handler := newTestHandler(t, "https://example.invalid", &memoryAuditor{failAfter: -1}, nil)
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("健康状态 = %d %s", response.Code, response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"status", "rule_set_version", "policy", "audit"} {
		if _, exists := body[key]; !exists {
			t.Fatalf("健康响应缺少字段 %s: %#v", key, body)
		}
	}
	if len(body) != 4 || strings.Contains(response.Body.String(), testLocalToken) || strings.Contains(response.Body.String(), "upstream-key") {
		t.Fatalf("健康响应包含未授权字段: %#v", body)
	}
}

func newTestHandler(t *testing.T, upstream string, auditor Auditor, rules []storage.Rule) *Handler {
	return newTestHandlerWithLimits(t, upstream, auditor, rules, config.LimitsConfig{
		MaxCompressedBytes: 1 << 20, MaxDecompressedBytes: 1 << 20, MaxConcurrent: 10,
	})
}

func newTestHandlerWithLimits(t *testing.T, upstream string, auditor Auditor, rules []storage.Rule, limits config.LimitsConfig) *Handler {
	t.Helper()
	parsed, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := security.NewEngine(storage.RuleSet{
		Version: "1", DefaultAction: storage.DefaultAction, Rules: rules,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{
		Upstream: parsed, Client: upstreamClient(), Engine: engine, Audit: auditor,
		LocalToken: testLocalToken, UpstreamKey: "upstream-key", OSUser: "developer",
		Limits: limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func upstreamClient() *http.Client {
	return &http.Client{Transport: &http.Transport{DisableCompression: true}}
}

func performRequest(handler http.Handler, body []byte, encoding string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, responsesPath, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testLocalToken)
	request.Header.Set("Content-Type", "application/json")
	if encoding != "" {
		request.Header.Set("Content-Encoding", encoding)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func gzipBody(t *testing.T, body []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func decodeErrorCode(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var envelope map[string]map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope["error"]["code"].(string)
}
