package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
)

// 只保存稳定分类，错误字符串可能包含地址、凭证或请求内容，不能用于持久化诊断。
func ClassifyUpstreamError(ctx context.Context, err error, tlsFailed bool) string {
	if errors.Is(ctx.Err(), context.Canceled) {
		return "client_canceled"
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || timeoutStatus(err) == http.StatusGatewayTimeout {
		return "upstream_timeout"
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		return "upstream_dns_error"
	}
	if isConnectionRefused(err) {
		return "upstream_connection_refused"
	}
	var verificationError *tls.CertificateVerificationError
	var recordError tls.RecordHeaderError
	var alertError tls.AlertError
	var authorityError x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	var certificateError x509.CertificateInvalidError
	var rootsError x509.SystemRootsError
	if tlsFailed || errors.As(err, &verificationError) || errors.As(err, &recordError) || errors.As(err, &alertError) ||
		errors.As(err, &authorityError) || errors.As(err, &hostnameError) || errors.As(err, &certificateError) || errors.As(err, &rootsError) {
		return "upstream_tls_error"
	}
	return "upstream_error"
}

// UpstreamErrorDetail 返回不包含请求数据的固定错误说明。
func UpstreamErrorDetail(code string) string {
	switch code {
	case "upstream_dns_error":
		return "上游域名解析失败，请检查上游地址和 DNS 配置"
	case "upstream_connection_refused":
		return "上游拒绝连接，请检查地址、端口和服务是否启动"
	case "upstream_tls_error":
		return "上游 TLS 握手或证书校验失败"
	case "upstream_timeout":
		return "等待上游连接或响应超时"
	case "client_canceled":
		return "请求已取消或客户端已断开连接"
	default:
		return "上游连接、响应读取或客户端传输中断"
	}
}

func upstreamFailureResult(code, fallback string) string {
	if code == "client_canceled" {
		return "client_canceled"
	}
	return fallback
}
