package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/audit"
)

func createV3Audit(t *testing.T, path string) {
	t.Helper()
	createV2Audit(t, path)
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, statement := range []string{
		"ALTER TABLE audit_matches ADD COLUMN action TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE audit_matches ADD COLUMN reason TEXT NOT NULL DEFAULT ''",
		"INSERT INTO schema_migrations VALUES(3, '2026-01-01T00:00:00Z')",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAuditDiagnosticsMigrationPreservesHistoryAndPersistsNewRejections(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "data", "audit.db")
	createV3Audit(t, path)
	for range 2 {
		if err := CheckAudit(ctx, path); err != nil {
			t.Fatal(err)
		}
		old, err := QueryAuditDetail(ctx, path, 1)
		if err != nil || old.RequestPath != "" || old.RequestMethod != "" || old.HTTPStatus != 0 || len(old.Matches) != 1 {
			t.Fatalf("迁移改变历史记录或伪造了接口信息: %+v %v", old, err)
		}
	}
	store, err := OpenAudit(ctx, path, 36500, 100<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Write(audit.Event{EventType: "system_error", RequestID: "route-rejection", User: "tester", RuleSetVersion: "9",
		Action: "block", Result: "rejected", ErrorCode: "gateway_route_not_supported",
		RequestMethod: "POST", RequestPath: "/v1/alpha/search", HTTPStatus: 404}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	page, err := QueryAudit(ctx, path, AuditFilter{RequestID: "route-rejection"})
	if err != nil || len(page.Items) != 1 || page.Items[0].RequestPath != "/v1/alpha/search" || page.Items[0].RequestMethod != "POST" || page.Items[0].HTTPStatus != 404 {
		t.Fatalf("拒绝诊断未持久化: %+v %v", page, err)
	}
}

func TestAuditDiagnosticsMigrationRollsBackPartialColumns(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "data", "audit.db")
	createV3Audit(t, path)
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("ALTER TABLE audit_events ADD COLUMN request_path TEXT NOT NULL DEFAULT ''"); err != nil {
		t.Fatal(err)
	}
	if err := migrateDatabase(ctx, db, auditDatabase); err == nil {
		t.Fatal("重复字段应使迁移失败")
	}
	if _, err := db.Exec("SELECT request_method FROM audit_events"); err == nil {
		t.Fatal("失败迁移留下了部分新增字段")
	}
	if version, err := readMigrationVersion(ctx, db); err != nil || version != 3 {
		t.Fatalf("失败迁移改变版本: %d %v", version, err)
	}
}
