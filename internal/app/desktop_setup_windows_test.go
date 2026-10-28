package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/settings"
)

func TestDesktopSetupRequiresSavedConnectionAndSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(t.TempDir(), "private-data")
	store, err := settings.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	values, token, key, err := store.Load(ctx)
	if err != nil || !values.SetupRequired {
		t.Fatal("新环境必须处于待配置状态", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = settings.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	values, token, key, err = store.Load(ctx)
	if err != nil || !values.SetupRequired {
		t.Fatal("未完成配置时再次启动仍须配置", err)
	}
	c := &desktopController{store: store, values: values, token: token, key: key}
	defer c.stop()
	cfg, err := store.Config(values)
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeDesktopDatabases(cfg); err != nil {
		t.Fatal(err)
	}
	const origin = "http://127.0.0.1:38123"
	handler := c.managementHandler(origin, "setup-session")
	manage := func(method, path string, body any, wantStatus int) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(body)
		request := httptest.NewRequest(method, origin+"/api/"+path, bytes.NewReader(raw))
		request.Header.Set("Authorization", "Bearer setup-session")
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != wantStatus {
			t.Fatalf("管理接口状态不正确: %s %d %s", path, response.Code, response.Body.String())
		}
		return response
	}
	if result := manage("GET", "status", nil, 200); !strings.Contains(result.Body.String(), `"setup_required":true`) || !strings.Contains(result.Body.String(), `"running":false`) {
		t.Fatal("新环境状态应明确显示待配置且未运行")
	}
	manage("POST", "start", nil, 200)
	if c.active != nil || !strings.Contains(c.lastError, "请先在连接设置") {
		t.Fatal("未完成配置时不能手动启动代理")
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	defer upstream.Close()
	manage("POST", "check-upstream", map[string]string{"upstream": upstream.URL + "/v1"}, 200)
	loaded, _, _, err := store.Load(ctx)
	if err != nil || !loaded.SetupRequired || c.active != nil || c.values.Upstream != values.Upstream {
		t.Fatal("检查连接不能保存地址、结束首次配置或启动代理", err)
	}
	invalid := values
	invalid.Upstream = ""
	manage("PUT", "settings", invalid, 400)
	loaded, _, _, err = store.Load(ctx)
	if err != nil || !loaded.SetupRequired || !c.values.SetupRequired {
		t.Fatal("保存无效设置不能结束首次配置", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	values.Listen = listener.Addr().String()
	listener.Close()
	values.Upstream = upstream.URL + "/v1"
	// 客户端不必发送首次配置标记，也不必提供网关密钥。
	manage("PUT", "settings", values, 200)
	loaded, _, loadedKey, err := store.Load(ctx)
	if err != nil || loaded.SetupRequired || c.values.SetupRequired || c.active == nil || loadedKey != "" {
		t.Fatal("保存客户端认证设置后应结束配置并启动代理", err)
	}
	if result := manage("GET", "status", nil, 200); !strings.Contains(result.Body.String(), `"setup_required":false`) || !strings.Contains(result.Body.String(), `"running":true`) {
		t.Fatal("配置完成后状态应显示本地代理已运行")
	}
	if err := c.stop(); err != nil {
		t.Fatal(err)
	}
	// 模拟重新读取已保存状态，仍能使用既有设置启动，不重复引导。
	c.values = loaded
	if err := c.restart(); err != nil {
		t.Fatal("已配置环境应能再次启动", err)
	}
}
