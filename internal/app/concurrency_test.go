package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/audit"
	"github.com/xiaotaowang/prompt-auditing/internal/config"
	"github.com/xiaotaowang/prompt-auditing/internal/gateway"
	"github.com/xiaotaowang/prompt-auditing/internal/security"
	"github.com/xiaotaowang/prompt-auditing/internal/settings"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

type concurrencyAudit struct{}

func (concurrencyAudit) Write(audit.Event) error { return nil }
func (concurrencyAudit) Healthy() bool           { return true }
func (concurrencyAudit) MarkUnhealthy()          {}

type concurrencyTransport func(*http.Request) (*http.Response, error)

func (f concurrencyTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestManagementConcurrencyIndependentOfCaptureAndGatewayInstance(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ready, finish, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	upstream, _ := url.Parse("https://upstream.invalid")
	engine, err := security.NewEngine(storage.RuleSet{Version: "1", DefaultAction: storage.DefaultAction})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: concurrencyTransport(func(r *http.Request) (*http.Response, error) {
		close(ready)
		select {
		case <-finish:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"data":[]}`))}, nil
	})}
	options := gateway.Options{Upstream: upstream, Client: client, Engine: engine, Audit: concurrencyAudit{}, ClientAuth: true, OSUser: "test",
		Limits: config.LimitsConfig{MaxCompressedBytes: 1024, MaxDecompressedBytes: 1024, MaxConcurrent: 4}}
	handler, err := gateway.NewHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	active := &desktopGateway{handler: handler}
	active.running.Store(true)
	c := &desktopController{active: active, values: settings.Values{MaxConcurrentRequests: 4}}
	request := httptest.NewRequest("GET", "http://gateway.invalid/v1/models", nil).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer private-key")
	request.Header.Set("session_id", "session-private")
	go func() { defer close(done); handler.ServeHTTP(httptest.NewRecorder(), request) }()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("请求未到达模拟上游")
	}
	manage := c.managementHandler("http://127.0.0.1:38123", "management-session")
	check := func(method, body string, want int, running bool) {
		t.Helper()
		r := httptest.NewRequest(method, "http://127.0.0.1:38123/api/live-logs", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer management-session")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		manage.ServeHTTP(w, r)
		var result struct {
			Concurrency gateway.ConcurrencySnapshot `json:"concurrency"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 200 {
			t.Fatalf("管理接口错误: %d %s", w.Code, w.Body.String())
		}
		if result.Concurrency.Current != want || result.Concurrency.Running != running || result.Concurrency.Limit != 4 || result.Concurrency.Items == nil || result.Concurrency.Sessions == nil {
			t.Fatalf("并发统计错误: %+v", result.Concurrency)
		}
		for _, secret := range []string{"private-key", "session-private"} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("管理接口泄露原始标识或凭证")
			}
		}
	}
	check("GET", "", 1, true)
	check("PUT", `{"enabled":true}`, 1, true)
	check("DELETE", "", 1, true)
	check("PUT", `{"enabled":false}`, 1, true)
	// 重启后的实例不应混入尚未结束的旧实例统计。
	replacement, err := gateway.NewHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.active = &desktopGateway{handler: replacement}
	c.active.running.Store(true)
	c.mu.Unlock()
	check("GET", "", 0, true)
	c.mu.Lock()
	c.active = nil
	c.mu.Unlock()
	check("GET", "", 0, false)
	close(finish)
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("旧实例请求未完成")
	}
	if handler.ConcurrencySnapshot().Current != 0 {
		t.Fatal("旧实例未释放名额")
	}
}
