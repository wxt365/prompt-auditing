package security

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestMaskBeforeOtherRules(t *testing.T) {
	for _, test := range []struct {
		name, input, target, blocked, action string
		maskEnabled                          bool
	}{
		{"替换后放行", "stage_source_7f3", "stage_safe_7f3", "stage_source_7f3", ActionMask, true},
		{"替换结果仍违禁", "stage_source_7f3", "stage_denied_7f3", "stage_denied_7f3", ActionBlock, true},
		{"替换后仍有其他违禁词", "stage_source_7f3 stage_denied_7f3", "stage_safe_7f3", "stage_denied_7f3", ActionBlock, true},
		{"替换保留源词", "stage_source_7f3", "stage_source_7f3_safe", "stage_source_7f3", ActionBlock, true},
		{"禁用替换仍阻断", "stage_source_7f3", "stage_safe_7f3", "stage_source_7f3", ActionBlock, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, reverse := range []bool{false, true} {
				rules := []storage.Rule{
					{ID: "block", Name: "测试拦截", Type: "keyword", Action: ActionBlock, Enabled: true, Keywords: []string{test.blocked}},
					{ID: "mask", Name: "测试替换", Type: "keyword_mapping", Action: ActionMask, Enabled: test.maskEnabled, Mappings: []storage.Mapping{{Source: "stage_source_7f3", Target: test.target}}},
				}
				if reverse {
					rules[0], rules[1] = rules[1], rules[0]
				}
				engine := mustEngine(t, rules)
				raw, _ := json.Marshal(map[string]any{"input": test.input})
				payload := mustPayload(t, string(raw))
				before, _ := Marshal(payload)
				decision := inspect(t, engine, payload)
				afterInspection, _ := Marshal(payload)
				if decision.Action != test.action || string(before) != string(afterInspection) {
					t.Fatalf("动作错误或检查修改了原文: %+v", decision)
				}
				if err := engine.ApplyMask(payload, decision); err != nil {
					t.Fatal(err)
				}
				if test.action == ActionBlock {
					after, _ := Marshal(payload)
					if string(after) != string(before) {
						t.Fatal("阻断请求应保留原文供审计")
					}
				} else {
					value, err := getString(payload.Root, "/input")
					if err != nil || value != test.target || len(decision.Matches) != 1 || decision.Matches[0].RuleID != "mask" {
						t.Fatalf("替换或审计命中错误: value=%s decision=%+v err=%v", value, decision, err)
					}
				}
			}
		})
	}
}

func TestMaskFirstRegexAndWarningsInspectFinalText(t *testing.T) {
	for _, action := range []string{ActionBlock, ActionWarn} {
		engine := mustEngine(t, []storage.Rule{
			{ID: "mask", Type: "regex", Enabled: true, Action: ActionMask, Pattern: `stage_source_([0-9]+)`, Replacement: "stage_target_${1}"},
			{ID: "post", Type: "regex", Enabled: true, Action: action, Pattern: `stage_target_[0-9]+`},
			{ID: "old", Type: "keyword", Enabled: true, Action: ActionWarn, Keywords: []string{"stage_source_42"}},
		})
		payload := mustPayload(t, `{"input":"stage_source_42"}`)
		decision := inspect(t, engine, payload)
		want := ActionMask
		if action == ActionBlock {
			want = ActionBlock
		}
		if decision.Action != want || len(decision.Matches) != 2 || decision.Matches[1].RuleID != "post" || decision.Matches[1].Original != "stage_target_42" {
			t.Fatalf("正则或告警未检查替换结果: %+v", decision)
		}
	}
}

func TestMaskFirstUsesSelectedNonCascadingReplacements(t *testing.T) {
	engine := mustEngine(t, []storage.Rule{
		{ID: "long", Type: "keyword_mapping", Enabled: true, Action: ActionMask, Mappings: []storage.Mapping{{Source: "stage_source_7f3", Target: "stage_safe_7f3"}}},
		{ID: "short", Type: "keyword_mapping", Enabled: true, Action: ActionMask, Mappings: []storage.Mapping{{Source: "stage_source", Target: "stage_denied"}}},
		{ID: "cascade", Type: "keyword_mapping", Enabled: true, Action: ActionMask, Mappings: []storage.Mapping{{Source: "stage_safe_7f3", Target: "stage_denied"}}},
		{ID: "block", Type: "keyword", Enabled: true, Action: ActionBlock, Keywords: []string{"stage_source_7f3", "stage_denied"}},
	})
	payload := mustPayload(t, `{"input":"stage_source_7f3"}`)
	decision := inspect(t, engine, payload)
	if decision.Action != ActionMask || len(decision.Matches) != 1 || decision.Matches[0].RuleID != "long" {
		t.Fatalf("重叠区间审计或非级联行为错误: %+v", decision)
	}
	if err := engine.ApplyMask(payload, decision); err != nil {
		t.Fatal(err)
	}
	value, err := getString(payload.Root, "/input")
	if err != nil || value != "stage_safe_7f3" {
		t.Fatalf("实际替换与预演不同: %s %v", value, err)
	}
}

func TestMaskFirstNormalizedSourceAndMatchBudget(t *testing.T) {
	engine := mustEngine(t, []storage.Rule{
		{ID: "mask", Type: "keyword_mapping", Enabled: true, Action: ActionMask, Mappings: []storage.Mapping{{Source: "stage_source_7f3", Target: "stage_safe_7f3"}}},
		{ID: "block", Type: "keyword", Enabled: true, Action: ActionBlock, Keywords: []string{"stage_source_7f3"}},
	})
	decision := inspect(t, engine, mustPayload(t, `{"input":"ＳＴＡＧＥ_source_7f3"}`))
	if decision.Action != ActionMask || len(decision.Matches) != 1 {
		t.Fatalf("规范化匹配后未放行: %+v", decision)
	}
	engine = mustEngine(t, []storage.Rule{
		{ID: "mask", Type: "keyword_mapping", Enabled: true, Action: ActionMask, Mappings: []storage.Mapping{{Source: "x", Target: "y"}}},
		{ID: "block", Type: "keyword", Enabled: true, Action: ActionBlock, Keywords: []string{"y"}},
	})
	payload := Payload{Texts: []Text{{Path: "/input", Value: strings.Repeat("x", MaxMatchesPerInspection/2+1), Maskable: true}}}
	if _, err := engine.Inspect(context.Background(), payload); !errors.Is(err, ErrMatchLimitExceeded) {
		t.Fatalf("两阶段未共用命中上限: %v", err)
	}
	// 检查失败不能修改调用方传入的文本快照。
	if !reflect.DeepEqual(payload.Texts, []Text{{Path: "/input", Value: strings.Repeat("x", MaxMatchesPerInspection/2+1), Maskable: true}}) {
		t.Fatal("预演修改了输入文本")
	}
}
