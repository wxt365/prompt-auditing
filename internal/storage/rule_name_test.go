package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/audit"
)

// 用旧版建表语句构造真实文件，避免新版初始化掩盖迁移问题。
func createV1Database(t *testing.T, path string, kind databaseKind) *sql.DB {
	t.Helper()
	if err := createEmptyFile(path); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := configureDatabase(context.Background(), db, true); err != nil {
		t.Fatal(err)
	}
	statements := []string{"CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"}
	if kind == policyDatabase {
		statements = append(statements, policyMigrationV1...)
	} else {
		statements = append(statements, auditMigrationV1...)
	}
	statements = append(statements, "INSERT INTO schema_migrations VALUES(1, '2026-01-01T00:00:00Z')")
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestRuleNameMigrationPreservesOldDataAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(t.TempDir(), "private-data")
	policyPath, auditPath := filepath.Join(directory, "policy.db"), filepath.Join(directory, "audit.db")
	policyDB := createV1Database(t, policyPath, policyDatabase)
	for _, statement := range []string{
		`INSERT INTO policy_rules VALUES('custom.rule', 'keyword', 'warn', 1, 0, NULL, NULL, 'old', 'old')`,
		`INSERT INTO policy_keywords VALUES('custom.rule', '客户A', 0)`,
		`UPDATE policy_meta SET value='7' WHERE key='rule_set_version'`,
	} {
		if _, err := policyDB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	policyDB.Close()
	auditDB := createV1Database(t, auditPath, auditDatabase)
	for _, statement := range []string{
		`INSERT INTO audit_events(id, request_id, event_type, occurred_at, user_name, rule_set_version, action, result, match_count, duration_ms) VALUES(1, 'old-request', 'decision', '2026-01-01T00:00:00Z', 'tester', '7', 'warn', 'forwarding', 1, 0)`,
		`INSERT INTO audit_matches VALUES(1, 0, 'custom.rule', 'keyword', '客户A')`,
	} {
		if _, err := auditDB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	auditDB.Close()
	for range 2 {
		store, err := OpenPolicy(ctx, policyPath)
		if err != nil {
			t.Fatal(err)
		}
		set, err := store.Load(ctx)
		if err != nil || set.Version != "7" || len(set.Rules) != 4 {
			t.Fatalf("迁移改变了旧规则集: %+v %v", set, err)
		}
		for _, rule := range set.Rules {
			if rule.ID == "custom.rule" {
				if rule.Name != "custom.rule" || !reflect.DeepEqual(rule.Keywords, []string{"客户A"}) {
					t.Fatalf("自定义旧规则未保留: %+v", rule)
				}
			} else if rule.Name == "" || rule.Name == rule.ID {
				t.Fatalf("默认规则未设置中文名: %+v", rule)
			}
		}
		version, err := readMigrationVersion(ctx, store.db)
		if err != nil || version != schemaVersion {
			t.Fatalf("迁移版本错误: %d %v", version, err)
		}
		store.Close()
		if err := CheckAudit(ctx, auditPath); err != nil {
			t.Fatal(err)
		}
		detail, err := QueryAuditDetail(ctx, auditPath, 1)
		if err != nil || detail.RuleSetVersion != "7" || len(detail.Matches) != 1 || detail.Matches[0].RuleName != "" || detail.Matches[0].RuleID != "custom.rule" || detail.Matches[0].Keyword != "客户A" {
			t.Fatalf("旧审计信息改变或被补写名称: %+v %v", detail, err)
		}
		page, err := QueryAudit(ctx, auditPath, AuditFilter{RuleName: "custom"})
		if err != nil || len(page.Items) != 1 {
			t.Fatalf("旧审计标识回退筛选失败: %+v %v", page, err)
		}
	}
}

func TestRuleNameMigrationFailureRollsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "policy.db")
	db := createV1Database(t, path, policyDatabase)
	if _, err := db.Exec(`CREATE TRIGGER reject_name BEFORE UPDATE ON policy_rules BEGIN SELECT RAISE(ABORT, '测试迁移回滚'); END`); err != nil {
		t.Fatal(err)
	}
	if err := migrateDatabase(context.Background(), db, policyDatabase); err == nil {
		t.Fatal("预期迁移失败")
	}
	if _, err := db.Exec("SELECT name FROM policy_rules"); err == nil {
		t.Fatal("迁移失败后留下了部分字段")
	}
	version, err := readMigrationVersion(context.Background(), db)
	if err != nil || version != 1 {
		t.Fatalf("迁移失败改变了版本: %d %v", version, err)
	}
	if _, err := db.Exec("DROP TRIGGER reject_name"); err != nil {
		t.Fatal(err)
	}
	if err := migrateDatabase(context.Background(), db, policyDatabase); err != nil {
		t.Fatal(err)
	}
}

func TestAuditRuleNameSnapshotSurvivesRenameAndDeletion(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(t.TempDir(), "data")
	policyPath, auditPath := filepath.Join(directory, "policy.db"), filepath.Join(directory, "audit.db")
	if err := InitDatabases(ctx, policyPath, auditPath); err != nil {
		t.Fatal(err)
	}
	policy, err := OpenPolicy(ctx, policyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer policy.Close()
	rule := Rule{ID: "rule.stable", Name: "敏感字替换", Type: "keyword_mapping", Action: "mask", Enabled: true, Mappings: []Mapping{{Source: "客户A", Target: "客户"}}}
	if err := policy.ReplaceRules(ctx, []Rule{rule}); err != nil {
		t.Fatal(err)
	}
	store, err := OpenAudit(ctx, auditPath, 30, 100<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Write(audit.Event{RequestID: "snapshot", EventType: "decision", User: "tester", RuleSetVersion: "2", Action: "mask", Result: "forwarding", MatchCount: 1,
		Matches: []audit.Match{{RuleID: rule.ID, RuleName: rule.Name, Category: rule.Type, MatchedKeyword: "客户A"}}}); err != nil {
		t.Fatal(err)
	}
	rule.Name = "新的名称"
	for _, rules := range [][]Rule{{rule}, {}} {
		if err := policy.ReplaceRules(ctx, rules); err != nil {
			t.Fatal(err)
		}
		page, err := QueryAudit(ctx, auditPath, AuditFilter{RuleName: "敏感字"})
		if err != nil || len(page.Items) != 1 {
			t.Fatalf("历史名称无法筛选: %+v %v", page, err)
		}
		detail, err := QueryAuditDetail(ctx, auditPath, page.Items[0].ID)
		if err != nil || len(detail.Matches) != 1 || detail.Matches[0].RuleName != "敏感字替换" || detail.Matches[0].Keyword != "客户A" {
			t.Fatalf("修改当前规则改变了历史名称或关键字: %+v %v", detail, err)
		}
		for _, name := range []string{"新的名称", "敏感字' OR 1=1 --", "%"} {
			page, err := QueryAudit(ctx, auditPath, AuditFilter{RuleName: name})
			if err != nil || len(page.Items) != 0 {
				t.Fatalf("名称筛选未按字面值处理: %+v %v", page, err)
			}
		}
	}
}

func TestRuleNameValidation(t *testing.T) {
	rule := Rule{ID: "valid", Type: "keyword", Action: "block", Keywords: []string{"test"}}
	for _, name := range []string{"敏感字替换", strings.Repeat("中", 128), ""} {
		rule.Name = name
		if err := validateRule(rule); err != nil {
			t.Fatalf("有效名称被拒绝: %v", err)
		}
	}
	for _, name := range []string{strings.Repeat("中", 129), " \t ", "名称\n换行", string([]byte{0xff})} {
		rule.Name = name
		if err := validateRule(rule); err == nil {
			t.Fatal("无效名称未拒绝")
		}
	}
}
