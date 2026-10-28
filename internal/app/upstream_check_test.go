package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestUpstreamProbeOnlyChecksHTTPReachability(t *testing.T) {
	for _, status := range []int{200, 301, 401, 403, 404, 405, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var redirected atomic.Int32
			redirect := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
			defer redirect.Close()
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodHead || r.URL.Path != "/prefix/v1/models" || r.Header.Get("Authorization") != "" || r.ContentLength != 0 {
					t.Error("连接检查不应调用模型或发送认证和正文")
				}
				w.Header().Set("Location", redirect.URL)
				w.WriteHeader(status)
			}))
			defer upstream.Close()
			result := probeUpstream(context.Background(), upstream.URL+"/prefix/v1/", upstream.Client())
			if !result.Reachable || result.HTTPStatus != status || result.ErrorCode != "" || redirected.Load() != 0 || !strings.Contains(result.Message, "未验证密钥、模型或完整请求") {
				t.Fatalf("检查结果或重定向处理错误: %+v redirected=%d", result, redirected.Load())
			}
		})
	}
}

func TestUpstreamProbeReportsSafeFailure(t *testing.T) {
	for _, test := range []struct {
		name, code string
		err        error
	}{
		{"DNS", "upstream_dns_error", &net.DNSError{Err: "probe failure private_credential_92", Name: "probe.invalid"}},
		{"超时", "upstream_timeout", context.DeadlineExceeded},
		{"未知", "upstream_error", errors.New("probe failure private_credential_92")},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: upstreamProbeTransport(func(r *http.Request) (*http.Response, error) {
				deadline, ok := r.Context().Deadline()
				if !ok || time.Until(deadline) > upstreamCheckTimeout {
					t.Fatal("连接检查必须有超时限制")
				}
				return nil, test.err
			})}
			result := probeUpstream(context.Background(), "https://probe.invalid/v1", client)
			raw, _ := json.Marshal(result)
			if result.Reachable || result.ErrorCode != test.code || strings.Contains(string(raw), "private_credential_92") {
				t.Fatalf("检查失败分类或脱敏错误: %+v", result)
			}
		})
	}
}

func TestUpstreamCheckManagementAuthenticationAndValidation(t *testing.T) {
	const origin = "http://127.0.0.1:38123"
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "" || r.Method != http.MethodHead {
			t.Error("管理检查不得发送凭证或模型请求")
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()
	c := &desktopController{key: "probe_private_key_92"}
	handler := c.managementHandler(origin, "probe-session")
	for _, test := range []struct {
		name, body, session, requestOrigin string
		status                             int
	}{
		{"未认证", `{"upstream":"` + upstream.URL + `"}`, "", origin, 401},
		{"外部来源", `{"upstream":"` + upstream.URL + `"}`, "Bearer probe-session", "https://foreign.invalid", 403},
		{"空地址", `{"upstream":""}`, "Bearer probe-session", origin, 400},
		{"非法协议", `{"upstream":"file:///probe"}`, "Bearer probe-session", origin, 400},
		{"URL 内凭证", `{"upstream":"https://probe:credential@probe.invalid/v1"}`, "Bearer probe-session", origin, 400},
		{"URL 查询参数", `{"upstream":"https://probe.invalid/v1?token=private_92"}`, "Bearer probe-session", origin, 400},
		{"不接受密钥", `{"upstream":"` + upstream.URL + `","upstream_key":"probe_private_key_92"}`, "Bearer probe-session", origin, 400},
		{"已收到认证拒绝", `{"upstream":"` + upstream.URL + `"}`, "Bearer probe-session", origin, 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, origin+"/api/check-upstream", strings.NewReader(test.body))
			request.Header.Set("Authorization", test.session)
			request.Header.Set("Origin", test.requestOrigin)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || strings.Contains(response.Body.String(), c.key) {
				t.Fatalf("管理检查状态或凭证保护错误: status=%d body=%s", response.Code, response.Body.String())
			}
			if test.status == 200 {
				var result upstreamCheckResult
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || !result.Reachable || result.HTTPStatus != 401 {
					t.Fatal("401 只表示需要认证，网络与 HTTP 响应已可达", err)
				}
			}
		})
	}
	if calls.Load() != 1 || c.active != nil {
		t.Fatal("无效检查不应访问上游，连接检查不应启动代理")
	}
}

func TestUpstreamCheckDoesNotBlockOtherManagementRequests(t *testing.T) {
	const origin = "http://127.0.0.1:38123"
	entered, release := make(chan struct{}), make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(entered)
		<-release
	}))
	defer upstream.Close()
	defer close(release)
	c := &desktopController{}
	handler := c.managementHandler(origin, "probe-session")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		request := httptest.NewRequest(http.MethodPost, origin+"/api/check-upstream", strings.NewReader(`{"upstream":"`+upstream.URL+`"}`)).WithContext(ctx)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer probe-session")
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("连接检查没有进入模拟上游")
	}
	request := httptest.NewRequest(http.MethodGet, origin+"/api/live-logs", nil)
	request.Header.Set("Authorization", "Bearer probe-session")
	response := httptest.NewRecorder()
	queried := make(chan struct{})
	go func() { handler.ServeHTTP(response, request); close(queried) }()
	select {
	case <-queried:
		if response.Code != 200 {
			t.Fatal("连接检查期间其他管理请求应正常响应")
		}
	case <-time.After(time.Second):
		t.Fatal("连接检查持锁阻塞了其他管理请求")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("取消检查后未及时结束")
	}
}

type upstreamProbeTransport func(*http.Request) (*http.Response, error)

func (f upstreamProbeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
