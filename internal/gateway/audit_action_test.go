package gateway

import (
	"context"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/security"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestAuditMatchesKeepEffectiveActionsAndUnsafeMaskReason(t *testing.T) {
	engine, err := security.NewEngine(storage.RuleSet{Version: "1", DefaultAction: "allow", Rules: []storage.Rule{
		{ID: "mask", Type: "keyword_mapping", Action: "mask", Enabled: true, Mappings: []storage.Mapping{{Source: "stage_source_7f3", Target: "stage_safe_7f3"}}},
		{ID: "deny", Type: "regex", Action: "block", Enabled: true, Pattern: "stage_denied_7f3"},
		{ID: "warn", Type: "private_ipv4", Action: "warn", Enabled: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := security.Extract([]byte(`{"model":"stage_source_7f3","input":"stage_source_7f3 stage_denied_7f3 10.0.0.1"}`))
	if err != nil {
		t.Fatal(err)
	}
	decision, err := engine.Inspect(context.Background(), payload)
	if err != nil || decision.Action != "block" {
		t.Fatal("未生成阻断决策", err)
	}
	hits := auditMatches(decision.Matches)
	if len(hits) != 4 {
		t.Fatalf("不同动作的同规则命中被错误合并：%d", len(hits))
	}
	counts := map[string]int{}
	for _, hit := range hits {
		counts[hit.Action+"/"+hit.Reason]++
	}
	if counts["block/unsafe_mask"] != 1 || counts["block/rule_block"] != 1 || counts["mask/"] != 1 || counts["warn/"] != 1 {
		t.Fatal("未保留替换、告警、直接阻断与安全提升的真实动作")
	}
}
