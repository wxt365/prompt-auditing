package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadResolvesDatabasePathsFromConfigDirectory(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "gateway.yaml")
	body := `version: 1
listen: 127.0.0.1:8080
upstream: https://api.openai.com/v1
policy_db: data/policy.db
audit_db: data/audit.db
max_body_bytes: 5242880
max_concurrent_requests: 10
audit_retention_days: 30
audit_max_bytes: 104857600
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PolicyDB != filepath.Join(directory, "data", "policy.db") || cfg.AuditDB != filepath.Join(directory, "data", "audit.db") {
		t.Fatalf("数据库路径解析错误: %#v", cfg)
	}
}

func TestLoadAcceptsFixedHTTPAndHTTPSUpstreams(t *testing.T) {
	for _, upstream := range []string{
		"https://api.openai.com/v1",
		"http://192.168.137.250:33000/v1/",
	} {
		t.Run(upstream, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "gateway.yaml")
			body := "version: 1\nlisten: 127.0.0.1:8080\nupstream: " + upstream + "\npolicy_db: p.db\naudit_db: a.db\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Upstream != upstream {
				t.Fatalf("upstream 被意外修改: got=%q want=%q", cfg.Upstream, upstream)
			}
		})
	}
}

func TestLoadRejectsUnsupportedOrNonFixedUpstreams(t *testing.T) {
	for _, upstream := range []string{
		"ftp://192.168.137.250/v1",
		"http:///v1",
		"http://user:password@192.168.137.250/v1",
		"http://192.168.137.250/v1?tenant=a",
		"http://192.168.137.250/v1#fragment",
	} {
		t.Run(upstream, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "gateway.yaml")
			body := "version: 1\nlisten: 127.0.0.1:8080\nupstream: " + upstream + "\npolicy_db: p.db\naudit_db: a.db\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatalf("不安全或非固定 upstream 未被拒绝: %s", upstream)
			}
		})
	}
}

func TestLoadRejectsUnknownFieldAndSharedDatabase(t *testing.T) {
	for _, body := range []string{
		"version: 1\nlisten: 127.0.0.1:8080\nupstream: https://api.openai.com/v1\npolicy_db: same.db\naudit_db: same.db\n",
		"version: 1\nlisten: 127.0.0.1:8080\nupstream: https://api.openai.com/v1\npolicy_db: p.db\naudit_db: a.db\nunknown: true\n",
		"version: 1\nlisten: 0.0.0.0:8080\nupstream: https://api.openai.com/v1\npolicy_db: p.db\naudit_db: a.db\n",
		"version: 1\nlisten: 127.0.0.1:0\nupstream: https://api.openai.com/v1\npolicy_db: p.db\naudit_db: a.db\n",
		"version: 1\nlisten: 127.0.0.1:65536\nupstream: https://api.openai.com/v1\npolicy_db: p.db\naudit_db: a.db\n",
		"version: 1\nlisten: 127.0.0.1:8080\nupstream: https://api.openai.com/v1\npolicy_db: p.db\naudit_db: a.db\n---\nversion: 1\n",
	} {
		path := filepath.Join(t.TempDir(), "gateway.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("期望拒绝配置: %s", body)
		}
	}
}

func TestLoadRejectsDatabasePathsThatReferToSameFile(t *testing.T) {
	directory := t.TempDir()
	policyPath := filepath.Join(directory, "policy.db")
	auditPath := filepath.Join(directory, "audit.db")
	if err := os.WriteFile(policyPath, []byte("same file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(policyPath, auditPath); err != nil {
		t.Skipf("当前文件系统不支持硬链接: %v", err)
	}
	configPath := filepath.Join(directory, "gateway.yaml")
	body := `version: 1
listen: 127.0.0.1:8080
upstream: https://api.openai.com/v1
policy_db: policy.db
audit_db: audit.db
`
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil {
		t.Fatal("期望拒绝指向同一文件的数据库路径")
	}
}
