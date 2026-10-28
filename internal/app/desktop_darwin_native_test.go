//go:build darwin && cgo && native_e2e && keychain_e2e

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/settings"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestNativeDarwinDesktopManagementPersistsAndAuditsBothProtocols(t *testing.T) {
	for _, authMode := range []string{settings.AuthClient, settings.AuthGateway} {
		t.Run(authMode, func(t *testing.T) { testDarwinDesktopManagement(t, authMode) })
	}
}

func testDarwinDesktopManagement(t *testing.T, authMode string) {
	t.Helper()
	ctx := context.Background()
	directory := filepath.Join(t.TempDir(), "desktop-data")
	store, err := settings.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	values, token, key, err := store.Load(ctx)
	if err != nil || !values.SetupRequired || key != "" {
		t.Fatalf("首次配置错误: %v", err)
	}
	controller := &desktopController{store: store, values: values, token: token}
	defer controller.close()
	cfg, err := store.Config(values)
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeDesktopDatabases(cfg); err != nil {
		t.Fatal(err)
	}
	const secret = "darwin-native-test-upstream-key"
	forwarded := make(chan string, 4)
	const sse = "data: {\"ok\":true}\n\ndata: [DONE]\n\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer "+secret || strings.Contains(string(body), "测试内部系统") || !strings.Contains(string(body), "业务系统") {
			t.Error("上游凭证或替换正文错误")
		}
		forwarded <- r.URL.Path
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, sse)
	}))
	defer upstream.Close()
	management := httptest.NewUnstartedServer(nil)
	origin := "http://" + management.Listener.Addr().String()
	management.Config.Handler = controller.managementHandler(origin, "native-test-session")
	management.Start()
	defer management.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	manage := func(path string, value any) []byte {
		t.Helper()
		body, _ := json.Marshal(value)
		r, _ := http.NewRequest(http.MethodPut, origin+"/api/"+path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer native-test-session")
		r.Header.Set("Origin", origin)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		result, _ := io.ReadAll(response.Body)
		var outcome struct{ Error string }
		if err := json.Unmarshal(result, &outcome); err != nil || response.StatusCode != 200 || outcome.Error != "" {
			t.Fatalf("管理操作失败: status=%d err=%v body=%s", response.StatusCode, err, result)
		}
		return result
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	values.Listen = listener.Addr().String()
	listener.Close()
	values.Upstream, values.AuthMode = upstream.URL+"/v1/", authMode
	manage("settings", struct {
		settings.Values
		UpstreamKey string `json:"upstream_key"`
	}{values, secret})
	manage("rules", map[string]any{"rules": []storage.Rule{
		{Name: "客户阻断", Type: "keyword", Action: "block", Enabled: true, Keywords: []string{"客户A"}},
		{Name: "名称替换", Type: "keyword_mapping", Action: "mask", Enabled: true, Mappings: []storage.Mapping{{Source: "测试内部系统", Target: "业务系统"}}},
	}})
	for _, path := range []string{"/v1/responses", "/v1/chat/completions"} {
		for _, blocked := range []bool{false, true} {
			text, want := "测试内部系统", http.StatusOK
			if blocked {
				text, want = "客户A "+secret, http.StatusForbidden
			}
			payload := map[string]any{"model": "test-model", "stream": true}
			if path == "/v1/responses" {
				payload["input"] = text
			} else {
				payload["messages"] = []map[string]string{{"role": "user", "content": text}}
			}
			body, _ := json.Marshal(payload)
			r, _ := http.NewRequest(http.MethodPost, "http://"+values.Listen+path, bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			credential := secret
			if authMode == settings.AuthGateway {
				credential = token
			}
			r.Header.Set("Authorization", "Bearer "+credential)
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			result, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != want || (!blocked && string(result) != sse) {
				t.Fatalf("双协议代理错误: %s status=%d err=%v", path, response.StatusCode, err)
			}
			if !blocked {
				if got := <-forwarded; got != path {
					t.Fatalf("上游路径错误: %s", got)
				}
			} else if len(forwarded) != 0 {
				t.Fatal("阻断请求不应发送上游")
			}
		}
	}
	if err := controller.stop(); err != nil {
		t.Fatal(err)
	}
	page, err := storage.QueryAudit(ctx, cfg.AuditDB, storage.AuditFilter{Action: "block"})
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("双协议审计记录错误: count=%d err=%v", len(page.Items), err)
	}
	for _, event := range page.Items {
		body, err := storage.QueryAuditRequestBody(ctx, cfg.AuditDB, event.ID)
		if err != nil || strings.Contains(body.Body, secret) || !strings.Contains(body.Body, "客户A") {
			t.Fatalf("阻断正文未正确脱除凭证: %v", err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(directory, "settings.db"))
	if err != nil || bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte(token)) {
		t.Fatal("设置库不应包含明文凭证")
	}
	reopened, err := settings.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	loaded, loadedToken, loadedKey, err := reopened.Load(ctx)
	if err != nil || loaded.SetupRequired || loadedToken != token || loaded.AuthMode != authMode || loaded.Upstream != values.Upstream {
		t.Fatalf("重新打开未恢复设置: %v", err)
	}
	wantKey := ""
	if authMode == settings.AuthGateway {
		wantKey = secret
	}
	if loadedKey != wantKey {
		t.Fatal("认证模式对应的密钥保存行为错误")
	}
}
