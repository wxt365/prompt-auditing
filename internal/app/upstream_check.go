package app

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/config"
	"github.com/xiaotaowang/prompt-auditing/internal/gateway"
)

const upstreamCheckTimeout = 5 * time.Second

type upstreamCheckResult struct {
	Reachable  bool   `json:"reachable"`
	HTTPStatus int    `json:"http_status,omitempty"`
	ErrorCode  string `json:"error_code,omitempty"`
	Message    string `json:"message"`
	DurationMS int64  `json:"duration_ms"`
}

func checkDesktopUpstream(w http.ResponseWriter, r *http.Request) error {
	var input struct {
		Upstream string `json:"upstream"`
	}
	if err := readDesktopJSON(w, r, &input); err != nil {
		return err
	}
	input.Upstream = strings.TrimSpace(input.Upstream)
	if err := config.ValidateUpstream(input.Upstream); err != nil {
		return err
	}
	client, err := newUpstreamHTTPClient(upstreamCheckTimeout)
	if err != nil {
		return errors.New("无法初始化连接检查，请检查证书配置")
	}
	defer client.CloseIdleConnections()
	return writeDesktopJSON(w, probeUpstream(r.Context(), input.Upstream, client))
}

func probeUpstream(ctx context.Context, address string, client *http.Client) upstreamCheckResult {
	started := time.Now()
	checkCtx, cancel := context.WithTimeout(ctx, upstreamCheckTimeout)
	defer cancel()
	var tlsFailed atomic.Bool
	checkCtx = httptrace.WithClientTrace(checkCtx, &httptrace.ClientTrace{
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) { tlsFailed.Store(err != nil) },
	})
	// 只检查网络与 HTTP 响应，不携带模型请求、认证信息，也不读取响应正文。
	request, err := http.NewRequestWithContext(checkCtx, http.MethodHead, strings.TrimRight(address, "/")+"/models", nil)
	if err != nil {
		return upstreamCheckResult{ErrorCode: "invalid_upstream", Message: "上游地址无效"}
	}
	probeClient := *client
	probeClient.Timeout = upstreamCheckTimeout
	probeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := probeClient.Do(request)
	result := upstreamCheckResult{DurationMS: time.Since(started).Milliseconds()}
	if err != nil {
		result.ErrorCode = gateway.ClassifyUpstreamError(checkCtx, err, tlsFailed.Load())
		result.Message = gateway.UpstreamErrorDetail(result.ErrorCode)
		return result
	}
	defer response.Body.Close()
	result.Reachable, result.HTTPStatus = true, response.StatusCode
	result.Message = "已收到上游 HTTP 响应；仅验证网络与 HTTP 可达，未验证密钥、模型或完整请求"
	return result
}
