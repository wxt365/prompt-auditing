package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/settings"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

const lifecycleOrigin = "http://127.0.0.1:38123"

// 使用临时数据库和被信号控制的本地上游，观察真实在途请求的停止等待。
func newLifecycleController(t *testing.T) (*desktopController, http.Handler, <-chan struct{}, func()) {
	t.Helper()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"ok\":true}\n\ndata: [DONE]\n\n")
	}))
	t.Cleanup(upstream.Close)
	store, err := settings.Open(filepath.Join(t.TempDir(), "private-data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	values, token, key, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	values.Listen = listener.Addr().String()
	_ = listener.Close()
	values.SetupRequired = false
	values.Upstream = upstream.URL + "/v1"
	if err := store.Save(context.Background(), values, token, key); err != nil {
		t.Fatal(err)
	}
	cfg, err := store.Config(values)
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeDesktopDatabases(cfg); err != nil {
		t.Fatal(err)
	}
	policy, err := storage.OpenPolicy(context.Background(), cfg.PolicyDB)
	if err != nil {
		t.Fatal(err)
	}
	// 不依赖用户默认规则的具体内容。
	if err := policy.ReplaceRules(context.Background(), []storage.Rule{}); err != nil {
		t.Fatal(err)
	}
	if err := policy.Close(); err != nil {
		t.Fatal(err)
	}
	c := &desktopController{store: store, values: values, token: token, key: key}
	t.Cleanup(c.close)
	t.Cleanup(finish)
	if err := c.restart(); err != nil {
		t.Fatal(err)
	}
	c.requestLog().SetEnabled(true)
	return c, c.managementHandler(lifecycleOrigin, "probe_session_92"), entered, finish
}

func lifecycleRequest(handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, lifecycleOrigin+"/api/"+path, bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer probe_session_92")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", lifecycleOrigin)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func startLifecycleRequest(t *testing.T, c *desktopController, entered <-chan struct{}) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	address := "http://" + c.state().values.Listen + "/v1/responses"
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	go func() {
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, address, strings.NewReader(`{"model":"probe_model_92","input":"probe_text_92","stream":true}`))
		if err != nil {
			done <- err
			return
		}
		r.Header.Set("Authorization", "Bearer probe_credential_92")
		r.Header.Set("Content-Type", "application/json")
		client := &http.Client{Transport: &http.Transport{Proxy: nil}}
		defer client.CloseIdleConnections()
		response, err := client.Do(r)
		if err == nil {
			_, err = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK {
				err = errors.New("在途请求未成功完成")
			}
		}
		done <- err
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatal("请求未进入受控上游", err)
	case <-time.After(3 * time.Second):
		t.Fatal("请求未及时到达受控上游")
	}
	return done
}

func waitLifecycleState(t *testing.T, c *desktopController, match func(desktopSnapshot) bool) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if match(c.state()) {
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("未观察到预期的生命周期状态")
		}
	}
}

func requireLifecycleResponse(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	var result struct{ Error string }
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Error != "" {
		t.Fatalf("管理操作失败: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestDesktopDrainKeepsManagementQueriesAvailable(t *testing.T) {
	for _, operation := range []string{"saving_settings", "saving_rules", "stopping", "restarting"} {
		t.Run(operation, func(t *testing.T) {
			c, handler, entered, release := newLifecycleController(t)
			previousVersion := c.state().active.version
			requestDone := startLifecycleRequest(t, c, entered)
			method, path, body := "POST", "stop", any(nil)
			switch operation {
			case "saving_settings":
				values := c.state().values
				values.MaxConcurrentRequests++
				method, path, body = "PUT", "settings", values
			case "saving_rules":
				method, path, body = "PUT", "rules", map[string]any{"rules": []storage.Rule{{
					ID: "probe_rule_92", Name: "probe_rule_92", Type: "keyword", Action: "warn", Enabled: true, Keywords: []string{"probe_nevermatch_92"},
				}}}
			case "restarting":
				path = "start"
			}
			operationDone := make(chan *httptest.ResponseRecorder, 1)
			go func() { operationDone <- lifecycleRequest(handler, method, path, body) }()
			waitLifecycleState(t, c, func(state desktopSnapshot) bool { return state.operation == operation && state.active == nil })
			for _, query := range []string{"status", "settings", "live-logs", "audits", "rules"} {
				responseDone := make(chan *httptest.ResponseRecorder, 1)
				go func() { responseDone <- lifecycleRequest(handler, "GET", query, nil) }()
				select {
				case response := <-responseDone:
					requireLifecycleResponse(t, response)
					if query == "status" && !strings.Contains(response.Body.String(), `"operation":"`+operation+`"`) {
						t.Fatal("状态查询未标明当前保存或启停操作")
					}
				case <-time.After(time.Second):
					t.Fatalf("%s 等待在途请求时阻塞了 %s 查询", operation, query)
				}
			}
			select {
			case <-operationDone:
				t.Fatal("在途请求完成前生命周期操作提前结束")
			default:
			}
			release()
			select {
			case response := <-operationDone:
				requireLifecycleResponse(t, response)
			case <-time.After(3 * time.Second):
				t.Fatal("释放在途请求后生命周期操作未及时完成")
			}
			if err := <-requestDone; err != nil {
				t.Fatal(err)
			}
			state := c.state()
			if state.operation != "" || (state.active == nil) != (operation == "stopping") {
				t.Fatal("操作完成后的运行状态错误")
			}
			response := lifecycleRequest(handler, "GET", "audits", nil)
			var page storage.AuditPage
			if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Items[0].Result != "completed" || page.Items[0].RuleSetVersion != previousVersion {
				t.Fatal("在途请求未完整落库或使用了重启后的规则版本")
			}
			if operation == "saving_rules" && state.active.version == previousVersion {
				t.Fatal("规则保存成功后活动代理没有加载新版本")
			}
		})
	}
}

func TestDesktopConcurrentSavesRemainSerialized(t *testing.T) {
	c, handler, entered, release := newLifecycleController(t)
	requestDone := startLifecycleRequest(t, c, entered)
	first, second := c.state().values, c.state().values
	first.MaxConcurrentRequests = 11
	second.MaxConcurrentRequests = 12
	firstDone, secondDone := make(chan *httptest.ResponseRecorder, 1), make(chan *httptest.ResponseRecorder, 1)
	go func() { firstDone <- lifecycleRequest(handler, "PUT", "settings", first) }()
	waitLifecycleState(t, c, func(state desktopSnapshot) bool { return state.operation == "saving_settings" && state.active == nil })
	go func() { secondDone <- lifecycleRequest(handler, "PUT", "settings", second) }()
	select {
	case <-secondDone:
		t.Fatal("第二次保存越过了正在等待旧请求结束的第一次保存")
	case <-time.After(50 * time.Millisecond):
	}
	if c.state().values != first {
		t.Fatal("等待中的保存覆盖了正在应用的配置")
	}
	release()
	for _, done := range []<-chan *httptest.ResponseRecorder{firstDone, secondDone} {
		select {
		case response := <-done:
			requireLifecycleResponse(t, response)
		case <-time.After(3 * time.Second):
			t.Fatal("串行保存未结束")
		}
	}
	if err := <-requestDone; err != nil {
		t.Fatal(err)
	}
	loaded, _, _, err := c.store.Load(context.Background())
	state := c.state()
	if err != nil || loaded != second || state.values != second || state.active == nil || !state.active.running.Load() {
		t.Fatal("串行保存后的落库配置与活动代理不一致", err)
	}
}

func TestDesktopCloseRejectsQueuedRestartAndReclaimsGateway(t *testing.T) {
	c, handler, entered, release := newLifecycleController(t)
	requestDone := startLifecycleRequest(t, c, entered)
	stopDone := make(chan error, 1)
	go func() { stopDone <- c.stop() }()
	waitLifecycleState(t, c, func(state desktopSnapshot) bool { return state.operation == "stopping" && state.active == nil })
	restartDone := make(chan error, 1)
	go func() { restartDone <- c.restart() }()
	closed := make(chan struct{})
	go func() { c.close(); close(closed) }()
	waitLifecycleState(t, c, func(state desktopSnapshot) bool { return state.closing })
	if response := lifecycleRequest(handler, "GET", "status", nil); response.Code != http.StatusServiceUnavailable {
		t.Fatal("退出开始后仍接收管理请求")
	}
	release()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("退出没有完成在途请求回收")
	}
	if err := <-stopDone; err != nil {
		t.Fatal(err)
	}
	if err := <-restartDone; !errors.Is(err, errDesktopClosing) {
		t.Fatal("退出后队列中的重启未被拒绝", err)
	}
	if err := <-requestDone; err != nil || c.state().active != nil {
		t.Fatal("退出后仍有活动代理或在途请求未正常结束", err)
	}
}

type lifecycleSlowWriter struct {
	*httptest.ResponseRecorder
	entered chan struct{}
	release chan struct{}
}

func (w *lifecycleSlowWriter) Write(data []byte) (int, error) {
	close(w.entered)
	<-w.release
	return w.ResponseRecorder.Write(data)
}

func TestDesktopSlowManagementResponseDoesNotHoldControllerLock(t *testing.T) {
	for _, test := range []struct{ method, path string }{{"GET", "status"}, {"POST", "stop"}} {
		t.Run(test.path, func(t *testing.T) {
			c, handler, _, _ := newLifecycleController(t)
			w := &lifecycleSlowWriter{httptest.NewRecorder(), make(chan struct{}), make(chan struct{})}
			var once sync.Once
			release := func() { once.Do(func() { close(w.release) }) }
			defer release()
			r := httptest.NewRequest(test.method, lifecycleOrigin+"/api/"+test.path, nil)
			r.Header.Set("Authorization", "Bearer probe_session_92")
			done := make(chan struct{})
			go func() { handler.ServeHTTP(w, r); close(done) }()
			select {
			case <-w.entered:
			case <-time.After(time.Second):
				t.Fatal("管理响应未进入受控写入")
			}
			stopped := make(chan error, 1)
			go func() { stopped <- c.stop() }()
			select {
			case err := <-stopped:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("慢管理响应持锁阻塞了代理停止")
			}
			// 释放响应后再等协程结束，避免测试退出时仍在写响应。
			release()
			<-done
		})
	}
}

func TestDesktopInvalidSavePreservesRunningGateway(t *testing.T) {
	c, handler, _, _ := newLifecycleController(t)
	before := c.state()
	invalid := before.values
	invalid.Upstream = ""
	if response := lifecycleRequest(handler, "PUT", "settings", invalid); response.Code != http.StatusBadRequest {
		t.Fatal("无效连接设置未被拒绝")
	}
	invalidRules := []storage.Rule{{ID: "probe_rule_92", Name: "probe_rule_92", Type: "keyword", Action: "invalid", Enabled: true, Keywords: []string{"probe_word_92"}}}
	if response := lifecycleRequest(handler, "PUT", "rules", map[string]any{"rules": invalidRules}); response.Code != http.StatusBadRequest {
		t.Fatal("无效规则未被拒绝")
	}
	after := c.state()
	if after.values != before.values || after.active != before.active || after.operation != "" || !after.active.running.Load() {
		t.Fatal("保存失败改变了当前配置、活动代理或留下进行中状态")
	}
	loaded, _, _, err := c.store.Load(context.Background())
	if err != nil || loaded != before.values {
		t.Fatal("保存失败改变了落库配置", err)
	}
	response := lifecycleRequest(handler, "GET", "rules", nil)
	var rules storage.RuleSet
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &rules) != nil || rules.Version != before.active.version || len(rules.Rules) != 0 {
		t.Fatal("无效规则改变了已保存规则或规则版本")
	}
	if err := c.stop(); err != nil {
		t.Fatal("失败保存后无法正常停止代理", err)
	}
}
