//go:build !windows

package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/audit"
)

func TestInitDatabasesCreatesVerifiedIndependentSchemas(t *testing.T) {
	ctx := context.Background()
	policyPath, auditPath := testDatabasePaths(t)
	if err := InitDatabases(ctx, policyPath, auditPath); err != nil {
		t.Fatal(err)
	}
	if err := InitDatabases(ctx, policyPath, auditPath); err == nil {
		t.Fatal("重复初始化必须拒绝覆盖数据库")
	}
	for _, path := range []string{policyPath, auditPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("数据库权限 = %o，路径 = %s", info.Mode().Perm(), path)
		}
	}
	policy, err := OpenPolicy(ctx, policyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer policy.Close()
	set, err := policy.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if set.Version != "1" || len(set.Rules) != 5 {
		t.Fatalf("初始规则集错误: %#v", set)
	}
	if err := CheckAudit(ctx, auditPath); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejectsEmptyDatabasesWithoutInitializingThem(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(t.TempDir(), "database")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		open func(string) error
	}{
		{name: "policy", open: func(path string) error {
			store, err := OpenPolicy(ctx, path)
			if store != nil {
				_ = store.Close()
			}
			return err
		}},
		{name: "audit", open: func(path string) error { return CheckAudit(ctx, path) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(directory, test.name+".db")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := test.open(path); err == nil || !strings.Contains(err.Error(), "必须先执行 init") {
				t.Fatalf("空数据库未失败关闭: %v", err)
			}
			db, err := sql.Open("sqlite", sqliteDSN(path))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var schemaObjects, defaultRules int
			if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").Scan(&schemaObjects); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='policy_rules'").Scan(&defaultRules); err != nil {
				t.Fatal(err)
			}
			if schemaObjects != 0 || defaultRules != 0 {
				t.Fatalf("拒绝空库时写入了 Schema: objects=%d policy_rules=%d", schemaObjects, defaultRules)
			}
		})
	}
}

func TestPolicyWritesAndVersionIncrementAreAtomic(t *testing.T) {
	ctx := context.Background()
	policyPath, auditPath := testDatabasePaths(t)
	if err := InitDatabases(ctx, policyPath, auditPath); err != nil {
		t.Fatal(err)
	}
	store, err := OpenPolicy(ctx, policyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AddBlock(ctx, "keyword.customer", []string{"客户A", "项目B"}, false); err != nil {
		t.Fatal(err)
	}
	if err := store.AddReplacement(ctx, "mapping.one", []Mapping{{Source: "内部系统Ａ", Target: "业务系统"}}, false); err != nil {
		t.Fatal(err)
	}
	beforeFailure, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if beforeFailure.Version != "3" || len(beforeFailure.Rules) != 7 {
		t.Fatalf("写入后的快照错误: %#v", beforeFailure)
	}
	if err := store.AddReplacement(ctx, "mapping.conflict", []Mapping{{Source: "内部系统A", Target: "另一个系统"}}, false); err == nil {
		t.Fatal("NFKC 等价 source 必须触发唯一约束")
	}
	if err := store.SetEnabled(ctx, "missing", false); err == nil {
		t.Fatal("不存在的规则必须拒绝修改")
	}
	afterFailure, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterFailure.Version != beforeFailure.Version || len(afterFailure.Rules) != len(beforeFailure.Rules) {
		t.Fatalf("失败事务改变了规则或版本: before=%#v after=%#v", beforeFailure, afterFailure)
	}
}

func TestPolicyLoadReturnsOneTransactionalSnapshotDuringConcurrentWrites(t *testing.T) {
	ctx := context.Background()
	policyPath, auditPath := testDatabasePaths(t)
	if err := InitDatabases(ctx, policyPath, auditPath); err != nil {
		t.Fatal(err)
	}
	writer, err := OpenPolicy(ctx, policyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	reader, err := OpenPolicy(ctx, policyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	done := make(chan error, 1)
	go func() {
		for index := 0; index < 40; index++ {
			if err := writer.AddBlock(ctx, fmt.Sprintf("concurrent.%02d", index), []string{fmt.Sprintf("keyword-%02d", index)}, true); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	finished := false
	for !finished {
		set, err := reader.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		version, err := strconv.Atoi(set.Version)
		if err != nil {
			t.Fatal(err)
		}
		if version != len(set.Rules)-4 {
			t.Fatalf("规则快照混合了不同事务: version=%d rules=%d", version, len(set.Rules))
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			finished = true
		default:
		}
	}
}

func TestInvalidRuleSetsAreRejected(t *testing.T) {
	valid := Rule{ID: "keyword.valid", Type: "keyword", Action: "block", Enabled: true, Keywords: []string{"客户A"}}
	tests := []struct {
		name  string
		rules []Rule
	}{
		{name: "重复规则 ID", rules: []Rule{valid, valid}},
		{name: "非法正则", rules: []Rule{{ID: "regex.invalid", Type: "regex", Action: "block", Enabled: true, Pattern: "["}}},
		{name: "空映射", rules: []Rule{{ID: "mapping.empty", Type: "keyword_mapping", Action: "mask", Enabled: true}}},
		{name: "同一源对应多个目标", rules: []Rule{
			{ID: "mapping.one", Type: "keyword_mapping", Action: "mask", Enabled: true, Mappings: []Mapping{{Source: "内部系统A", Target: "业务系统"}}},
			{ID: "mapping.two", Type: "keyword_mapping", Action: "mask", Enabled: true, Mappings: []Mapping{{Source: "内部系统Ａ", Target: "其他系统"}}},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateRuleSet(RuleSet{Version: "1", DefaultAction: DefaultAction, Rules: test.rules}); err == nil {
				t.Fatalf("无效规则集未被拒绝: %#v", test.rules)
			}
		})
	}
}

func TestAuditEventAndMatchesCommitAtomically(t *testing.T) {
	ctx := context.Background()
	policyPath, auditPath := testDatabasePaths(t)
	if err := InitDatabases(ctx, policyPath, auditPath); err != nil {
		t.Fatal(err)
	}
	store, err := OpenAudit(ctx, auditPath, 30, 100<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	body := json.RawMessage(`{"model":"gpt-test","input":"客户A 项目B 客户A"}`)
	event := audit.Event{
		EventType: "decision", RequestID: "req_block", OccurredAt: "2026-08-02T08:00:00+08:00",
		User: "developer", RuleSetVersion: "1",
		Action: "block", Result: "blocked", MatchCount: 3, RequestBody: body,
		Matches: []audit.Match{
			{RuleID: "keyword.customer", Category: "keyword", MatchedKeyword: "客户A"},
			{RuleID: "keyword.customer", Category: "keyword", MatchedKeyword: "项目B"},
			{RuleID: "keyword.customer", Category: "keyword", MatchedKeyword: "客户A"},
		},
	}
	if err := store.WriteEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	record, err := store.LatestBlocked(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if record.RequestID != "req_block" || string(record.RequestBody) != string(body) || strings.Join(record.MatchedKeywords, ",") != "客户A,项目B" {
		t.Fatalf("阻断审计查询错误: %#v", record)
	}
	var matchCount int
	if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_matches").Scan(&matchCount); err != nil {
		t.Fatal(err)
	}
	if matchCount != 2 {
		t.Fatalf("审计明细未去重: %d", matchCount)
	}
	var occurredAt string
	if err := store.db.QueryRowContext(ctx, "SELECT occurred_at FROM audit_events WHERE request_id='req_block'").Scan(&occurredAt); err != nil {
		t.Fatal(err)
	}
	if occurredAt != "2026-08-02T00:00:00Z" {
		t.Fatalf("审计时间未规范为 UTC: %s", occurredAt)
	}

	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER fail_audit_match BEFORE INSERT ON audit_matches
		BEGIN SELECT RAISE(ABORT, 'forced match failure'); END`); err != nil {
		t.Fatal(err)
	}
	failing := event
	failing.RequestID = "req_rollback"
	if err := store.WriteEvent(ctx, failing); err == nil {
		t.Fatal("期望模拟明细写入失败")
	}
	var eventCount int
	if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_events WHERE request_id='req_rollback'").Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 0 {
		t.Fatal("明细失败后主事件未回滚")
	}
}

func TestAuditCleanupDoesNotChangePolicy(t *testing.T) {
	ctx := context.Background()
	policyPath, auditPath := testDatabasePaths(t)
	if err := InitDatabases(ctx, policyPath, auditPath); err != nil {
		t.Fatal(err)
	}
	policy, err := OpenPolicy(ctx, policyPath)
	if err != nil {
		t.Fatal(err)
	}
	before, err := policy.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenAudit(ctx, auditPath, 1, 100<<20)
	if err != nil {
		t.Fatal(err)
	}
	old := audit.Event{
		EventType: "decision", RequestID: "req_old", OccurredAt: "2026-01-01T00:00:00Z",
		User: "developer", RuleSetVersion: before.Version, Action: "allow", Result: "forwarding",
	}
	if err := store.WriteEvent(ctx, old); err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC) }
	if err := store.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	var auditCount int
	if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_events").Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 0 {
		t.Fatalf("过期审计未清理: %d", auditCount)
	}
	after, err := policy.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before.Version != after.Version || len(before.Rules) != len(after.Rules) {
		t.Fatalf("审计清理改变了策略库: before=%#v after=%#v", before, after)
	}
	store.Close()
	policy.Close()
}

func TestAuditCleanupEnforcesMaximumDatabaseSize(t *testing.T) {
	ctx := context.Background()
	policyPath, auditPath := testDatabasePaths(t)
	if err := InitDatabases(ctx, policyPath, auditPath); err != nil {
		t.Fatal(err)
	}
	store, err := OpenAudit(ctx, auditPath, 30, 100<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	writeEvents := func(start, end int) {
		for index := start; index < end; index++ {
			body, err := json.Marshal(map[string]string{
				"model": "gpt-test",
				"input": strings.Repeat("敏感内容", 2048) + time.Now().Format(time.RFC3339Nano),
			})
			if err != nil {
				t.Fatal(err)
			}
			event := audit.Event{
				EventType: "decision", RequestID: fmt.Sprintf("req_%03d", index), User: "developer",
				RuleSetVersion: "1", Action: "block", Result: "blocked", MatchCount: 1,
				RequestBody: body, Matches: []audit.Match{{RuleID: "keyword.capacity", Category: "keyword", MatchedKeyword: "敏感内容"}},
			}
			if err := store.WriteEvent(ctx, event); err != nil {
				t.Fatal(err)
			}
		}
	}

	writeEvents(0, 40)
	if _, err := store.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	targetSize, err := sqliteFilesSize(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	writeEvents(40, 140)
	if _, err := store.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	oversized, err := sqliteFilesSize(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if oversized <= targetSize {
		t.Fatalf("测试数据未使审计库增长: target=%d oversized=%d", targetSize, oversized)
	}

	capacityLimit := oversized - 1
	store.maxBytes = capacityLimit
	if err := store.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	finalSize, err := sqliteFilesSize(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if finalSize > capacityLimit {
		t.Fatalf("容量清理后大小 = %d，上限 = %d", finalSize, capacityLimit)
	}
	var count int
	var earliest, latest sql.NullString
	if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*), MIN(request_id), MAX(request_id) FROM audit_events").Scan(&count, &earliest, &latest); err != nil {
		t.Fatal(err)
	}
	if count >= 140 {
		t.Fatalf("容量清理未删除审计事件: count=%d", count)
	}
	if count > 0 && (earliest.String == "req_000" || latest.String != "req_139") {
		t.Fatalf("容量清理未按时间淘汰旧事件: count=%d earliest=%s latest=%s", count, earliest.String, latest.String)
	}
}

func TestAuditMaintenanceStopsOnContextCancellation(t *testing.T) {
	ctx := context.Background()
	policyPath, auditPath := testDatabasePaths(t)
	if err := InitDatabases(ctx, policyPath, auditPath); err != nil {
		t.Fatal(err)
	}
	store, err := OpenAudit(ctx, auditPath, 30, 100<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	maintenanceCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		store.RunMaintenance(maintenanceCtx, time.Hour)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("审计维护任务未随 Context 取消退出")
	}
}

func TestHigherSchemaVersionAndBroadPermissionsAreRejected(t *testing.T) {
	ctx := context.Background()
	policyPath, auditPath := testDatabasePaths(t)
	if err := InitDatabases(ctx, policyPath, auditPath); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(policyPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE schema_migrations SET version=? WHERE version=?", schemaVersion+1, schemaVersion); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := OpenPolicy(ctx, policyPath); err == nil {
		t.Fatal("高于支持版本的策略库必须拒绝启动")
	}
	if err := os.Chmod(auditPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckAudit(ctx, auditPath); err == nil {
		t.Fatal("权限过宽的审计库必须拒绝启动")
	}
}

func TestAuditIndexWithWrongColumnsIsRejected(t *testing.T) {
	ctx := context.Background()
	policyPath, auditPath := testDatabasePaths(t)
	if err := InitDatabases(ctx, policyPath, auditPath); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(auditPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DROP INDEX idx_audit_events_occurred_at"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE INDEX idx_audit_events_occurred_at ON audit_events(request_id)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := CheckAudit(ctx, auditPath); err == nil {
		t.Fatal("列定义错误的必需索引必须拒绝启动")
	}
}

func testDatabasePaths(t *testing.T) (string, string) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "data")
	return filepath.Join(directory, "policy.db"), filepath.Join(directory, "audit.db")
}
