package storage

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
)

func TestBundledRulesSeedOnlyNewPolicyDatabase(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(t.TempDir(), "private-data")
	policyPath, auditPath := filepath.Join(directory, "policy.db"), filepath.Join(directory, "audit.db")
	if err := InitDatabases(ctx, policyPath, auditPath); err != nil {
		t.Fatal(err)
	}
	var expected []Rule
	if err := json.Unmarshal(bundledRulesJSON, &expected); err != nil {
		t.Fatal(err)
	}
	store, err := OpenPolicy(ctx, policyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	set, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if set.Version != "1" || len(set.Rules) != 5 || len(expected) != 2 {
		t.Fatal("新规则库的默认规则数量或版本错误")
	}
	privateIPv4Found := false
	for _, rule := range set.Rules {
		if rule.ID == "network.private-ipv4" {
			privateIPv4Found = true
			if rule.Enabled || rule.Action != "warn" {
				t.Fatal("私网 IPv4 检测应默认关闭，手动启用后仅告警")
			}
		}
	}
	if !privateIPv4Found {
		t.Fatal("缺少可手动启用的私网 IPv4 默认规则")
	}
	for _, want := range expected {
		if !want.Enabled {
			t.Fatal("新安装的两条敏感字规则均应默认启用")
		}
		found := false
		for _, got := range set.Rules {
			if got.ID == want.ID {
				found = true
				if !reflect.DeepEqual(got, want) {
					t.Fatal("内置规则的名称、动作、开关或匹配内容未完整保存")
				}
			}
		}
		if !found {
			t.Fatal("缺少内置规则")
		}
	}
	// 用户可以删除或关闭默认规则，重新打开和重复初始化均不得覆盖。
	if err := store.Delete(ctx, expected[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := store.SetEnabled(ctx, expected[1].ID, !expected[1].Enabled); err != nil {
		t.Fatal(err)
	}
	if err := store.SetEnabled(ctx, "network.private-ipv4", true); err != nil {
		t.Fatal(err)
	}
	before, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := InitDatabases(ctx, policyPath, auditPath); err == nil {
		t.Fatal("重复初始化必须拒绝覆盖")
	}
	store, err = OpenPolicy(ctx, policyPath)
	if err != nil {
		t.Fatal(err)
	}
	after, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("重新打开规则库覆盖了用户规则")
	}
}
