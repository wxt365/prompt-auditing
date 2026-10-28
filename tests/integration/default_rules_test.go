package integration_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/security"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestInitialRulesPositiveNegativeAndBoundarySamples(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(t.TempDir(), "data")
	policyPath := filepath.Join(directory, "policy.db")
	auditPath := filepath.Join(directory, "audit.db")
	if err := storage.InitDatabases(ctx, policyPath, auditPath); err != nil {
		t.Fatal(err)
	}
	policy, err := storage.OpenPolicy(ctx, policyPath)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := policy.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Close(); err != nil {
		t.Fatal(err)
	}
	engine, err := security.NewEngine(rules)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		input      string
		action     string
		matchCount int
	}{
		{name: "OpenAI_Key_正例", input: "sk-ABCDEFGHIJKLMNOPQRST", action: security.ActionBlock, matchCount: 1},
		{name: "OpenAI_Key_长度反例", input: "sk-ABCDEFGHIJKLMNOPQRS", action: security.ActionAllow},
		{name: "密码赋值大小写正例", input: "PASSWORD = secret123", action: security.ActionBlock, matchCount: 1},
		{name: "密码四字符边界", input: "pwd=abcd", action: security.ActionBlock, matchCount: 1},
		{name: "密码三字符反例", input: "pwd=abc", action: security.ActionAllow},
		{name: "RFC1918_默认关闭", input: "10.0.0.0 10.255.255.255 172.16.0.0 172.31.255.255 192.168.0.0 192.168.255.255", action: security.ActionAllow},
		{name: "公网与非法_IP_反例", input: "8.8.8.8 172.15.255.255 172.32.0.0 999.1.2.3", action: security.ActionAllow},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload, err := security.Extract([]byte(`{"model":"gpt-test","input":` + quoteJSON(test.input) + `}`))
			if err != nil {
				t.Fatal(err)
			}
			decision, err := engine.Inspect(ctx, payload)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Action != test.action || len(decision.Matches) != test.matchCount {
				t.Fatalf("默认规则处置错误: action=%s matches=%#v", decision.Action, decision.Matches)
			}
		})
	}
}

func quoteJSON(value string) string {
	result, _ := json.Marshal(value)
	return string(result)
}
