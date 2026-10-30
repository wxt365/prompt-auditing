//go:build windows

package settings

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDesktopSettingsPersistAndEncryptSecrets(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private-data")
	store, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	values, token, key, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(token) < 32 || key != "" {
		t.Fatal("首次初始化凭证不符合预期")
	}
	if values.Listen != "127.0.0.1:18080" {
		t.Fatalf("新安装默认监听地址错误: %s", values.Listen)
	}
	if values.MaxBodyBytes != 1073741824 {
		t.Fatalf("新安装默认请求限额错误: %d", values.MaxBodyBytes)
	}
	if !values.SetupRequired {
		t.Fatal("新安装必须先配置上游")
	}
	values.SetupRequired = false
	values.Listen = "127.0.0.1:8080"
	values.MaxBodyBytes = 5 << 20
	values.Upstream = "https://example.invalid/v1"
	values.AuthMode = AuthGateway
	const upstreamKey = "settings-test-private-upstream-key"
	if err := store.Save(context.Background(), values, token, upstreamKey); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"settings.db", "settings.db-journal"} {
		body, err := os.ReadFile(filepath.Join(directory, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte(token)) || bytes.Contains(body, []byte(upstreamKey)) {
			t.Fatalf("%s 包含明文凭证", name)
		}
	}
	reopened, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	loaded, loadedToken, loadedKey, err := reopened.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SetupRequired || loaded.Upstream != values.Upstream || loaded.Listen != values.Listen || loaded.MaxBodyBytes != values.MaxBodyBytes || loadedToken != token || loadedKey != upstreamKey {
		t.Fatal("配置或加密凭证未正确恢复")
	}
	if _, err := reopened.db.ExecContext(context.Background(), "UPDATE settings SET value=json_remove(value, '$.setup_required')"); err != nil {
		t.Fatal(err)
	}
	loaded, _, _, err = reopened.Load(context.Background())
	if err != nil || loaded.SetupRequired {
		t.Fatalf("旧设置缺少首次配置标记时应保持已配置状态: %v", err)
	}
	if _, err := reopened.db.ExecContext(context.Background(), "UPDATE settings SET value=json_remove(value, '$.auth_mode')"); err != nil {
		t.Fatal(err)
	}
	loaded, _, _, err = reopened.Load(context.Background())
	if err != nil || loaded.AuthMode != AuthGateway {
		t.Fatalf("升级必须保留已有网关密钥模式: %v", err)
	}
	loaded.Listen = "0.0.0.0:8080"
	if err := reopened.Save(context.Background(), loaded, token, upstreamKey); err == nil {
		t.Fatal("界面设置不得绕过回环监听限制")
	}
	loaded.Listen = values.Listen
	loaded.AuthMode = AuthClient
	if err := reopened.Save(context.Background(), loaded, token, upstreamKey); err != nil {
		t.Fatal(err)
	}
	loaded, _, loadedKey, err = reopened.Load(context.Background())
	if err != nil || loaded.AuthMode != AuthClient || loadedKey != "" {
		t.Fatalf("切换客户端认证应清除网关保存的密钥: %v", err)
	}
	if _, err := reopened.db.ExecContext(context.Background(), "UPDATE settings SET value=json_remove(value, '$.auth_mode')"); err != nil {
		t.Fatal(err)
	}
	loaded, _, _, err = reopened.Load(context.Background())
	if err != nil || loaded.AuthMode != AuthClient {
		t.Fatalf("旧版未配置密钥时应使用客户端认证: %v", err)
	}
}
