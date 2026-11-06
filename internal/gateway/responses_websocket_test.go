package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/xiaotaowang/prompt-auditing/internal/audit"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func webSocketTestUpstream(t *testing.T, tls bool) (*httptest.Server, chan []byte, chan *http.Request) {
	t.Helper()
	messages := make(chan []byte, 20)
	requests := make(chan *http.Request, 2)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(context.Background())
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for {
			_, body, err := conn.Read(ctx)
			if err != nil {
				return
			}
			messages <- body
			if err := writeWebSocket(ctx, conn, []byte(`{"type":"response.completed","response":{"id":"resp_test","status":"completed"}}`)); err != nil {
				return
			}
		}
	})
	var server *httptest.Server
	if tls {
		server = httptest.NewTLSServer(handler)
	} else {
		server = httptest.NewServer(handler)
	}
	t.Cleanup(server.Close)
	return server, messages, requests
}

func dialWebSocketGateway(t *testing.T, h *Handler, path, token string) (*websocket.Conn, context.Context) {
	t.Helper()
	gateway := httptest.NewServer(h)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	conn, _, err := websocket.Dial(ctx, gateway.URL+path, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + token}}})
	if err != nil {
		cancel()
		h.CloseWebSockets()
		gateway.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.CloseNow()
		h.CloseWebSockets()
		gateway.Close()
		cancel()
	})
	return conn, ctx
}

func webSocketRead(t *testing.T, ctx context.Context, conn *websocket.Conn) []byte {
	t.Helper()
	typ, body, err := conn.Read(ctx)
	if err != nil || typ != websocket.MessageText {
		t.Fatalf("读取 WebSocket 事件失败: %v %s", err, body)
	}
	return body
}

func auditSnapshot(a *memoryAuditor) []audit.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]audit.Event(nil), a.events...)
}

func TestResponsesWebSocketAliasesAuditEveryTurn(t *testing.T) {
	for _, tls := range []bool{false, true} {
		for _, path := range []string{responsesPath, responsesAliasPath} {
			for _, base := range []string{"/v1/", "/proxy/"} {
				t.Run(path+base+map[bool]string{true: "https", false: "http"}[tls], func(t *testing.T) {
					upstream, messages, requests := webSocketTestUpstream(t, tls)
					a := &memoryAuditor{failAfter: -1}
					h := newTestHandler(t, upstream.URL+base, a, []storage.Rule{
						{ID: "block", Type: "keyword", Enabled: true, Action: "block", Keywords: []string{"客户A"}},
						{ID: "mask", Type: "keyword_mapping", Enabled: true, Action: "mask", Mappings: []storage.Mapping{{Source: "内部系统", Target: "业务系统"}}},
						{ID: "warn", Type: "keyword", Enabled: true, Action: "warn", Keywords: []string{"提醒"}},
					})
					if tls {
						h.client.Transport = upstream.Client().Transport
					}
					h.requestLog = &RequestLog{}
					h.requestLog.SetEnabled(true)
					conn, ctx := dialWebSocketGateway(t, h, path, testLocalToken)
					request := <-requests
					wantPath := "/v1/responses"
					if base == "/proxy/" {
						wantPath = "/proxy/v1/responses"
					}
					if request.Method != "GET" || request.URL.Path != wantPath || request.Header.Get("Authorization") != "Bearer upstream-key" || request.Header.Get("Sec-WebSocket-Extensions") != "" {
						t.Fatalf("WebSocket 握手路径或认证错误: %s %s", request.Method, request.URL)
					}
					for _, test := range []struct{ event, action, contains string }{
						{`{ "type":"response.create", "model":"gpt-test", "input":"普通", "generate":false }`, "allow", "普通"},
						{`{"type":"response.create","model":"gpt-test","input":"客户A","stream_id":"main"}`, "block", ""},
						{`{"type":"response.create","model":"gpt-test","input":"内部系统","previous_response_id":"resp_test","stream_id":"main"}`, "mask", "业务系统"},
						{`{"type":"response.steer","input":[{"role":"user","content":"提醒"}],"response_id":"resp_test"}`, "warn", "提醒"},
					} {
						if err := writeWebSocket(ctx, conn, []byte(test.event)); err != nil {
							t.Fatal(err)
						}
						response := webSocketRead(t, ctx, conn)
						if test.action == "block" {
							if !bytes.Contains(response, []byte(`"code":"prompt_blocked"`)) || !bytes.Contains(response, []byte(`"stream_id":"main"`)) || len(messages) != 0 || bytes.Contains(response, []byte("客户A")) {
								t.Fatalf("WebSocket 阻断失败: %s", response)
							}
						} else {
							forward := <-messages
							if !bytes.Contains(response, []byte("response.completed")) || !bytes.Contains(forward, []byte(test.contains)) {
								t.Fatalf("WebSocket 转发失败: %s %s", forward, response)
							}
							if test.action != "mask" && string(forward) != test.event {
								t.Fatal("非脱敏事件未保留原始字节")
							}
							var object map[string]any
							_ = json.Unmarshal(forward, &object)
							if test.action == "mask" && (object["model"] != "gpt-test" || object["stream_id"] != "main" || object["previous_response_id"] != "resp_test") {
								t.Fatal("脱敏修改了协议字段")
							}
						}
						found := false
						for _, event := range auditSnapshot(a) {
							if event.EventType == "decision" && event.Action == test.action && event.Result != "websocket_connecting" {
								found = true
								if event.RequestPath != path {
									t.Fatalf("事件审计未保留原始路径: %+v", event)
								}
							}
						}
						if !found {
							t.Fatalf("缺少逐事件审计: %s", test.action)
						}
					}
					for _, entry := range h.requestLog.Snapshot().Items {
						if entry.Path != path {
							t.Fatalf("WebSocket 实时日志未保留原始路径: %+v", entry)
						}
					}
				})
			}
		}
	}
}

func TestResponsesWebSocketCannotBypassInspection(t *testing.T) {
	upstream, messages, _ := webSocketTestUpstream(t, false)
	a := &memoryAuditor{failAfter: -1}
	h := newTestHandler(t, upstream.URL, a, []storage.Rule{{ID: "mask", Type: "keyword_mapping", Enabled: true, Action: "mask", Mappings: []storage.Mapping{{Source: "secret", Target: "safe"}}}})
	conn, ctx := dialWebSocketGateway(t, h, responsesAliasPath, testLocalToken)
	for _, test := range []struct {
		body string
		typ  websocket.MessageType
	}{
		{`{"type":"response.create","model":"secret","input":"normal"}`, websocket.MessageText},
		{`{"type":"response.create","input":[{"type":"message","role":"secret","content":"normal"}]}`, websocket.MessageText},
		{`{"type":"response.create","input":"normal","metadata":{"secret":"value"}}`, websocket.MessageText},
		{`{"type":"response.create","input":"normal","tools":[{"type":"function","name":"secret"}]}`, websocket.MessageText},
		{`{"type":"response.create","input":"normal","stream_id":"secret"}`, websocket.MessageText},
		{`{"type":"response.create","input":"normal","extra":{"input":"secret"}}`, websocket.MessageText},
		{`{"type":"response.create","input":"safe","input":"secret"}`, websocket.MessageText},
		{`{"type":"unknown","input":"normal"}`, websocket.MessageText},
		{`{"type":"response.create","input":"normal"}`, websocket.MessageBinary},
		{`{"type":"response.create","input":`, websocket.MessageText},
	} {
		if err := conn.Write(ctx, test.typ, []byte(test.body)); err != nil {
			t.Fatal(err)
		}
		response := webSocketRead(t, ctx, conn)
		if !bytes.Contains(response, []byte(`"type":"error"`)) || len(messages) != 0 {
			t.Fatalf("未检测的内容被转发: %s %s", test.body, response)
		}
	}
	if err := writeWebSocket(ctx, conn, []byte(`{"type":"response.create","input":"normal"}`)); err != nil {
		t.Fatal(err)
	}
	_ = webSocketRead(t, ctx, conn)
	if len(messages) != 1 {
		t.Fatal("阻断后未能继续处理安全事件")
	}
}

func TestResponsesWebSocketAuditFailureAndShutdown(t *testing.T) {
	for _, mode := range []string{"audit", "engine", "shutdown", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			upstream, messages, _ := webSocketTestUpstream(t, false)
			a := &memoryAuditor{failAfter: -1}
			h := newTestHandler(t, upstream.URL, a, nil)
			h.limits.MaxCompressedBytes, h.limits.MaxDecompressedBytes = 256, 256
			if mode == "engine" {
				h.engine = panicSecurityEngine{}
			}
			conn, ctx := dialWebSocketGateway(t, h, responsesPath, testLocalToken)
			switch mode {
			case "engine":
				_ = writeWebSocket(ctx, conn, []byte(`{"type":"response.create","input":"normal"}`))
				response := webSocketRead(t, ctx, conn)
				if !bytes.Contains(response, []byte("security_engine_unavailable")) {
					t.Fatalf("未报告安全引擎故障: %s", response)
				}
			case "audit":
				a.mu.Lock()
				a.failAfter = 0
				a.mu.Unlock()
				_ = writeWebSocket(ctx, conn, []byte(`{"type":"response.create","input":"normal"}`))
				response := webSocketRead(t, ctx, conn)
				if !bytes.Contains(response, []byte("audit_unavailable")) {
					t.Fatalf("未报告审计故障: %s", response)
				}
			case "shutdown":
				done := make(chan struct{})
				go func() { h.CloseWebSockets(); close(done) }()
				select {
				case <-done:
				case <-ctx.Done():
					t.Fatal("停机没有回收 WebSocket")
				}
			case "oversize":
				_ = writeWebSocket(ctx, conn, []byte(strings.Repeat("x", 257)))
			}
			if _, _, err := conn.Read(ctx); err == nil {
				t.Fatal("应当关闭连接")
			}
			if len(messages) != 0 {
				t.Fatal("失败关闭时仍转发了事件")
			}
		})
	}
}

func TestResponsesWebSocketUpstreamDisconnectReleasesSession(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		<-release
		_ = conn.CloseNow()
	}))
	defer upstream.Close()
	a := &memoryAuditor{failAfter: -1}
	h := newTestHandler(t, upstream.URL, a, nil)
	conn, ctx := dialWebSocketGateway(t, h, responsesPath, testLocalToken)
	close(release)
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("上游断开后本地连接仍存活")
	}
	h.CloseWebSockets()
	found := false
	for _, event := range auditSnapshot(a) {
		found = found || event.ErrorCode == "upstream_stream_error"
	}
	h.webSockets.mu.Lock()
	active := len(h.webSockets.active)
	h.webSockets.mu.Unlock()
	if !found || active != 0 {
		t.Fatal("上游断开未记录或会话未释放")
	}
}

func TestResponsesWebSocketClientAuthAndConcurrency(t *testing.T) {
	upstream, _, requests := webSocketTestUpstream(t, false)
	h := newTestHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, nil)
	h.clientAuth = true
	h.semaphore = make(chan struct{}, 1)
	_, _ = dialWebSocketGateway(t, h, responsesPath, "client-key")
	if r := <-requests; r.Header.Get("Authorization") != "Bearer client-key" {
		t.Fatal("WebSocket 未沿用客户端认证")
	}
	r := httptest.NewRequest("POST", responsesPath, strings.NewReader(`{"input":"normal"}`))
	r.Header.Set("Authorization", "Bearer another-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatalf("WebSocket 未受并发限制: %d", w.Code)
	}
}

func TestResponsesWebSocketUsesConfiguredHandshakeTimeout(t *testing.T) {
	for _, timeout := range []time.Duration{0, 10 * time.Millisecond, 500 * time.Millisecond} {
		t.Run(timeout.String(), func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				timer := time.NewTimer(80 * time.Millisecond)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-r.Context().Done():
					return
				}
				conn, err := websocket.Accept(w, r, nil)
				if err != nil {
					return
				}
				defer conn.CloseNow()
				_, _, _ = conn.Read(r.Context())
			}))
			defer upstream.Close()
			base := newTestHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, nil)
			h, err := NewHandler(Options{Upstream: base.upstream, Client: base.client, Engine: base.engine, Audit: base.audit, Limits: base.limits, ClientAuth: true, OSUser: "test", UpstreamHeaderTimeout: timeout})
			if err != nil {
				t.Fatal(err)
			}
			if timeout == 0 && h.upstreamHeaderTimeout != 300*time.Second {
				t.Fatal("握手默认值不是300秒")
			}
			gateway := httptest.NewServer(h)
			defer gateway.Close()
			defer h.CloseWebSockets()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, response, err := websocket.Dial(ctx, gateway.URL+responsesPath, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + testLocalToken}}})
			if response != nil && response.Body != nil {
				defer response.Body.Close()
			}
			if timeout == 10*time.Millisecond {
				if err == nil {
					conn.CloseNow()
					t.Fatal("握手没有遵守配置的短超时")
				}
			} else {
				if err != nil {
					t.Fatalf("有效等待时间内的握手被提前中断: %v", err)
				}
				conn.CloseNow()
			}
		})
	}
}

func TestResponsesWebSocketRejectsHandshakeBeforeUpstream(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	for _, mode := range []string{"auth", "key", "origin", "audit", "version"} {
		t.Run(mode, func(t *testing.T) {
			a := &memoryAuditor{failAfter: -1}
			h := newTestHandler(t, upstream.URL, a, nil)
			r := httptest.NewRequest("GET", responsesPath, nil)
			r.Header = http.Header{
				"Authorization": {"Bearer " + testLocalToken}, "Connection": {"Upgrade"}, "Upgrade": {"websocket"},
				"Sec-Websocket-Key": {"dGhlIHNhbXBsZSBub25jZQ=="}, "Sec-Websocket-Version": {"13"},
			}
			status := 400
			switch mode {
			case "auth":
				r.Header.Del("Authorization")
				status = 401
			case "key":
				r.Header.Set("Sec-WebSocket-Key", "invalid")
			case "origin":
				r.Header.Set("Origin", "https://example.invalid")
			case "audit":
				a.failAfter = 0
				status = 503
			case "version":
				r.Header.Set("Sec-WebSocket-Version", "12")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != status {
				t.Fatalf("错误握手未拒绝: %d %s", w.Code, w.Body.String())
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("无效握手调用了上游")
	}
}

func TestResponsesWebSocketUpstreamErrorsRedactCredentials(t *testing.T) {
	for _, handshake := range []bool{false, true} {
		t.Run(map[bool]string{true: "handshake", false: "event"}[handshake], func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				const body = `{"type":"error","error":{"message":"upstream-key local-token-with-at-least-32-bytes"}}`
				if handshake {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(401)
					_, _ = io.WriteString(w, body)
					return
				}
				conn, err := websocket.Accept(w, r, nil)
				if err != nil {
					return
				}
				defer conn.CloseNow()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = writeWebSocket(ctx, conn, []byte(body))
				_, _, _ = conn.Read(ctx)
			}))
			defer upstream.Close()
			h := newTestHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, nil)
			var body []byte
			if handshake {
				server := httptest.NewServer(h)
				defer server.Close()
				defer h.CloseWebSockets()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, response, err := websocket.Dial(ctx, server.URL+responsesPath, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + testLocalToken}}})
				if err == nil || response == nil || response.StatusCode != 401 {
					t.Fatalf("上游握手错误未转发: %v %+v", err, response)
				}
				defer response.Body.Close()
				body, _ = io.ReadAll(response.Body)
			} else {
				conn, ctx := dialWebSocketGateway(t, h, responsesPath, testLocalToken)
				body = webSocketRead(t, ctx, conn)
			}
			if bytes.Contains(body, []byte("upstream-key")) || bytes.Contains(body, []byte(testLocalToken)) || !bytes.Contains(body, []byte(redactedCredential)) {
				t.Fatalf("上游 WebSocket 错误泄露凭证: %s", body)
			}
		})
	}
}
