package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/audit"
)

func createV2Audit(t *testing.T, path string) {
	t.Helper()
	db := createV1Database(t, path, auditDatabase)
	for _, query := range []string{
		"ALTER TABLE audit_matches ADD COLUMN rule_name TEXT NOT NULL DEFAULT ''",
		"INSERT INTO schema_migrations VALUES(2, '2026-01-01T00:00:00Z')",
		`INSERT INTO audit_events(id,request_id,event_type,occurred_at,user_name,rule_set_version,action,result,match_count,duration_ms) VALUES(1,'legacy','decision','2026-10-27T00:00:00Z','tester','8','block','blocked',1,0)`,
		`INSERT INTO audit_matches VALUES(1,0,'old-rule','regex',NULL,'历史规则')`,
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAuditActionMigrationPreservesUnknownHistoryAndNewSnapshots(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "data", "audit.db")
	createV2Audit(t, path)
	for range 2 {
		if err := CheckAudit(ctx, path); err != nil {
			t.Fatal(err)
		}
		detail, err := QueryAuditDetail(ctx, path, 1)
		if err != nil || len(detail.Matches) != 1 || detail.Matches[0].Action != "" || detail.Matches[0].Reason != "" || detail.Matches[0].RuleName != "历史规则" {
			t.Fatal("迁移未保留旧日志或错误猜测了历史动作", err)
		}
	}
	store, err := OpenAudit(ctx, path, 36500, 100<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	hits := []audit.Match{
		{RuleID: "same", RuleName: "测试替换", Category: "keyword_mapping", MatchedKeyword: "stage_source_7f3", Action: "mask"},
		{RuleID: "same", RuleName: "测试替换", Category: "keyword_mapping", MatchedKeyword: "stage_source_7f3", Action: "block", Reason: "unsafe_mask"},
		{RuleID: "regex", RuleName: "测试拦截", Category: "regex", Action: "block", Reason: "rule_block"},
		{RuleID: "warn", RuleName: "测试告警", Category: "private_ipv4", Action: "warn"},
	}
	if err := store.Write(audit.Event{EventType: "decision", RequestID: "new", User: "tester", RuleSetVersion: "9", Action: "block", Result: "blocked", RequestBody: []byte(`{"input":"normal"}`), MatchCount: 4, Matches: hits}); err != nil {
		t.Fatal(err)
	}
	page, err := QueryAudit(ctx, path, AuditFilter{RequestID: "new"})
	if err != nil || len(page.Items) != 1 {
		t.Fatal("新日志未保存", err)
	}
	detail, err := QueryAuditDetail(ctx, path, page.Items[0].ID)
	if err != nil || len(detail.Matches) != 4 {
		t.Fatal("不同判定的命中被合并", err)
	}
	for i, hit := range detail.Matches {
		if hit.Action != hits[i].Action || hit.Reason != hits[i].Reason || hit.RuleName != hits[i].RuleName {
			t.Fatal("历史动作快照不一致")
		}
	}
}

func TestAuditActionMigrationRollsBackOnFailure(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "data", "audit.db")
	createV2Audit(t, path)
	db, err := openAuditReader(ctx, path)
	if err == nil {
		db.Close()
		t.Fatal("未迁移的只读查询应拒绝")
	}
	// 制造第二条迁移语句失败，确认第一条新增字段也回滚。
	writer, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.Exec("ALTER TABLE audit_matches ADD COLUMN reason TEXT NOT NULL DEFAULT ''"); err != nil {
		t.Fatal(err)
	}
	if err := migrateDatabase(ctx, writer, auditDatabase); err == nil {
		t.Fatal("迁移应失败")
	}
	if _, err := writer.Exec("SELECT action FROM audit_matches"); err == nil {
		t.Fatal("迁移失败后留下部分字段")
	}
	version, err := readMigrationVersion(ctx, writer)
	if err != nil || version != 2 {
		t.Fatal("迁移失败改变了版本", err)
	}
}
