package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestClassifyUpstreamErrors(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	deadline, stop := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer stop()
	for _, test := range []struct {
		name, want string
		err        error
		ctx        context.Context
		tlsFailed  bool
	}{
		{name: "DNS", err: &net.DNSError{Err: "probe DNS failure", Name: "probe.invalid"}, want: "upstream_dns_error"},
		{name: "DNS 超时", err: &net.DNSError{IsTimeout: true}, want: "upstream_timeout"},
		{name: "连接拒绝", err: &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}, want: "upstream_connection_refused"},
		{name: "证书校验", err: &tls.CertificateVerificationError{Err: errors.New("probe certificate failure")}, want: "upstream_tls_error"},
		{name: "未知证书机构", err: x509.UnknownAuthorityError{Cert: &x509.Certificate{}}, want: "upstream_tls_error"},
		{name: "证书域名", err: x509.HostnameError{Certificate: &x509.Certificate{}, Host: "probe.invalid"}, want: "upstream_tls_error"},
		{name: "证书有效性", err: x509.CertificateInvalidError{Cert: &x509.Certificate{}, Reason: x509.Expired}, want: "upstream_tls_error"},
		{name: "根证书", err: x509.SystemRootsError{Err: errors.New("probe roots failure")}, want: "upstream_tls_error"},
		{name: "TLS 记录", err: tls.RecordHeaderError{Msg: "probe record failure"}, want: "upstream_tls_error"},
		{name: "TLS 告警", err: tls.AlertError(40), want: "upstream_tls_error"},
		{name: "握手阶段", err: errors.New("probe handshake failure"), tlsFailed: true, want: "upstream_tls_error"},
		{name: "握手超时", err: context.DeadlineExceeded, tlsFailed: true, want: "upstream_timeout"},
		{name: "请求超时", err: context.DeadlineExceeded, want: "upstream_timeout"},
		{name: "上下文超时", ctx: deadline, err: io.ErrUnexpectedEOF, want: "upstream_timeout"},
		{name: "客户端取消", ctx: canceled, err: context.Canceled, want: "client_canceled"},
		{name: "取消后读取失败", ctx: canceled, err: io.ErrUnexpectedEOF, want: "client_canceled"},
		{name: "上游内部取消不能归因于客户端", err: context.Canceled, want: "upstream_error"},
		{name: "未知错误", err: errors.New("probe unknown failure"), want: "upstream_error"},
		{name: "不根据错误文案猜测", err: errors.New("connection refused; TLS; DNS; timeout"), want: "upstream_error"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := test.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			// http.Client 返回的错误通常包裹在 url.Error 中。
			wrapped := &url.Error{Op: "Post", URL: "https://probe.invalid/v1/responses", Err: test.err}
			if got := ClassifyUpstreamError(ctx, wrapped, test.tlsFailed); got != test.want {
				t.Fatalf("分类=%s，期望=%s", got, test.want)
			}
		})
	}
}

func TestRealTLSFailuresAreClassified(t *testing.T) {
	for _, scenario := range []string{"certificate", "handshake", "plaintext"} {
		t.Run(scenario, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("TLS 失败时不应进入上游 HTTP 处理")
			}))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			if scenario == "plaintext" {
				// HTTP 服务收到 TLS 请求会返回协议错误，不会进入上面的处理函数。
				server.Start()
			} else {
				if scenario == "handshake" {
					server.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
						return nil, errors.New("probe handshake rejection")
					}}
				}
				server.StartTLS()
			}
			defer server.Close()
			target := "https://" + server.Listener.Addr().String()
			auditor := &memoryAuditor{failAfter: -1}
			handler := newTestHandler(t, target, auditor, nil)
			defer handler.client.CloseIdleConnections()
			response := performRequest(handler, []byte(`{"input":"probe_normal_92"}`), "")
			if response.Code != http.StatusBadGateway || decodeErrorCode(t, response) != "upstream_error" || len(auditor.events) != 2 {
				t.Fatalf("TLS 失败响应错误: status=%d events=%d", response.Code, len(auditor.events))
			}
			if event := auditor.events[1]; event.Result != "upstream_error" || event.ErrorCode != "upstream_tls_error" || event.UpstreamStatus != nil {
				t.Fatalf("实际 TLS 失败未正确分类: %+v", event)
			}
		})
	}
}

func TestRealConnectionAndHeaderTimeoutAreClassified(t *testing.T) {
	for _, scenario := range []string{"refused", "timeout"} {
		t.Run(scenario, func(t *testing.T) {
			var target, wantCode string
			wantStatus := http.StatusBadGateway
			if scenario == "refused" {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				target = "http://" + listener.Addr().String()
				if err := listener.Close(); err != nil {
					t.Fatal(err)
				}
				wantCode = "upstream_connection_refused"
			} else {
				release := make(chan struct{})
				server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					<-release
				}))
				defer server.Close()
				// 测试结束时主动释放处理函数，避免服务端等待读取断连事件。
				defer close(release)
				target, wantCode, wantStatus = server.URL, "upstream_timeout", http.StatusGatewayTimeout
			}
			auditor := &memoryAuditor{failAfter: -1}
			handler := newTestHandler(t, target, auditor, nil)
			handler.client.Transport = &http.Transport{ResponseHeaderTimeout: 50 * time.Millisecond}
			handler.client.Timeout = 5 * time.Second
			defer handler.client.CloseIdleConnections()
			response := performRequest(handler, []byte(`{"input":"probe_normal_92"}`), "")
			if response.Code != wantStatus || decodeErrorCode(t, response) != "upstream_error" || len(auditor.events) != 2 {
				t.Fatalf("实际连接失败响应错误: status=%d events=%d", response.Code, len(auditor.events))
			}
			if event := auditor.events[1]; event.ErrorCode != wantCode || event.UpstreamStatus != nil {
				t.Fatalf("实际连接失败分类错误: %+v", event)
			}
		})
	}
}
