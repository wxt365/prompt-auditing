//go:build windows

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/settings"
)

func TestDesktopPortConflictKeepsManagementAvailableAndCanRecover(t *testing.T) {
	store, err := settings.Open(filepath.Join(t.TempDir(), "private-data"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	values, token, key, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	values.Listen = occupied.Addr().String()
	values.SetupRequired = false
	c := &desktopController{store: store, values: values, token: token, key: key}
	defer c.stop()
	cfg, err := store.Config(values)
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeDesktopDatabases(cfg); err != nil {
		t.Fatal(err)
	}
	c.lastError = errorText(c.restart())
	if c.active != nil || !strings.Contains(c.lastError, "请更换本地监听端口") {
		t.Fatalf("端口占用未阻止代理启动或缺少提示: %s", c.lastError)
	}
	management := httptest.NewUnstartedServer(nil)
	origin := "http://" + management.Listener.Addr().String()
	management.Config.Handler = c.managementHandler(origin, "port-test-session")
	management.Start()
	defer management.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	request := func(method, path string, body any, status int) []byte {
		t.Helper()
		raw, _ := json.Marshal(body)
		r, _ := http.NewRequest(method, origin+"/api/"+path, bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer port-test-session")
		r.Header.Set("Content-Type", "application/json")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		result, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != status {
			t.Fatalf("管理接口不可用: %s %d %s %v", path, response.StatusCode, result, err)
		}
		return result
	}
	if raw := request("GET", "status", nil, 200); !bytes.Contains(raw, []byte("请更换本地监听端口")) {
		t.Fatalf("管理页未报告占用原因: %s", raw)
	}
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	values.Listen = free.Addr().String()
	free.Close()
	request("PUT", "settings", values, 200)
	if c.active == nil || c.lastError != "" {
		t.Fatalf("更换端口后未恢复代理: %s", c.lastError)
	}
	// 试图使用管理页端口时应提前拒绝，保留运行中的代理和现有设置。
	collision := values
	collision.Listen = management.Listener.Addr().String()
	if raw := request("PUT", "settings", collision, 400); !bytes.Contains(raw, []byte("Web 管理页")) {
		t.Fatalf("管理页冲突缺少明确提示: %s", raw)
	}
	if c.active == nil || c.values.Listen != values.Listen {
		t.Fatal("拒绝端口冲突时停止了当前代理或改变了设置")
	}
	loaded, _, _, err := store.Load(context.Background())
	if err != nil || loaded.Listen != values.Listen {
		t.Fatal("拒绝的端口覆盖了已保存配置")
	}
	response, err := client.Get("http://" + values.Listen + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("代理恢复后健康检查失败: %d", response.StatusCode)
	}
	request("GET", "settings", nil, 200)
}
