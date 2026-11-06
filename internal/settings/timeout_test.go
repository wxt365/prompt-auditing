package settings

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/config"
)

func TestSettingsHeaderTimeoutCompatibility(t *testing.T) {
	store := &Store{directory: t.TempDir()}
	for _, test := range []struct {
		extra   string
		want    int64
		invalid bool
	}{
		{"", 300, false},
		{`,"upstream_header_timeout_seconds":600`, 600, false},
		{`,"upstream_header_timeout_seconds":30`, 30, false},
		{`,"upstream_header_timeout_seconds":-1`, 0, true},
		{`,"upstream_header_timeout_seconds":9223372037`, 0, true},
	} {
		var values Values
		// 使用旧设置库的 JSON 形状，验证升级后无需数据库迁移。
		raw := `{"auth_mode":"client","listen":"127.0.0.1:18080","upstream":"https://example.invalid/v1","max_body_bytes":1073741824,"max_concurrent_requests":10,"audit_retention_days":30,"audit_max_bytes":104857600` + test.extra + `}`
		if err := json.Unmarshal([]byte(raw), &values); err != nil {
			t.Fatal(err)
		}
		cfg, err := store.Config(values)
		if test.invalid {
			if err == nil {
				t.Fatal("非法超时未拒绝")
			}
			continue
		}
		if err != nil || cfg.UpstreamHeaderTimeout != time.Duration(test.want)*time.Second || values.WithDefaults().UpstreamHeaderTimeoutSeconds != test.want {
			t.Fatalf("设置未正确传递: %+v %v", cfg, err)
		}
	}
	if (Values{}).WithDefaults().UpstreamHeaderTimeoutSeconds != config.DefaultUpstreamHeaderTimeoutSeconds {
		t.Fatal("新设置未使用默认超时")
	}
}
