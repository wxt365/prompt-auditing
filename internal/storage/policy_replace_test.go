package storage

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReplaceRulesCommitsVersionAndRollsBackPartialWrites(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(t.TempDir(), "private-data")
	policyPath := filepath.Join(directory, "policy.db")
	if err := InitDatabases(ctx, policyPath, filepath.Join(directory, "audit.db")); err != nil {
		t.Fatal(err)
	}
	store, err := OpenPolicy(ctx, policyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	before, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_rule BEFORE INSERT ON policy_rules
		WHEN NEW.id = 'reject' BEGIN SELECT RAISE(ABORT, '测试事务回滚'); END`); err != nil {
		t.Fatal(err)
	}
	rules := []Rule{
		{ID: "first", Type: "keyword", Action: "block", Enabled: true, Keywords: []string{"客户A"}},
		{ID: "reject", Type: "keyword_mapping", Action: "mask", Enabled: true, Mappings: []Mapping{{Source: "内部系统", Target: "业务系统"}}},
	}
	if err := store.ReplaceRules(ctx, rules); err == nil {
		t.Fatal("预期第二条规则插入失败")
	}
	after, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("保存失败改变了现有规则或版本")
	}
	if _, err := store.db.ExecContext(ctx, "DROP TRIGGER reject_rule"); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceRules(ctx, rules); err != nil {
		t.Fatal(err)
	}
	after, err = store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Version != "2" || !reflect.DeepEqual(after.Rules, rules) {
		t.Fatalf("完整规则集或版本未正确提交: %#v", after)
	}
}
