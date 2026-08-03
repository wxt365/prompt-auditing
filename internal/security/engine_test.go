package security

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestEngineBlockAndRecordAllKeywords(t *testing.T) {
	engine := mustEngine(t, []storage.Rule{{
		ID: "keyword.block-enterprise", Type: "keyword", Enabled: true,
		Action: ActionBlock, Keywords: []string{"客户A", "项目B"},
	}})
	payload := mustPayload(t, `{"model":"gpt-test","input":"客户Ａ属于项目B，客户Ａ需阻断"}`)
	decision := inspect(t, engine, payload)
	if decision.Action != ActionBlock {
		t.Fatalf("动作 = %s，期望 block", decision.Action)
	}
	if len(decision.Matches) != 3 {
		t.Fatalf("命中数 = %d，期望 3", len(decision.Matches))
	}
}

func TestKeywordMatchesFollowFirstOccurrenceOrder(t *testing.T) {
	engine := mustEngine(t, []storage.Rule{{
		ID: "keyword.block-enterprise", Type: "keyword", Enabled: true,
		Action: ActionBlock, Keywords: []string{"项目B", "客户A"},
	}})
	decision := inspect(t, engine, mustPayload(t, `{"model":"gpt-test","input":"客户A 项目B 客户A"}`))
	if len(decision.Matches) != 3 {
		t.Fatalf("命中数 = %d", len(decision.Matches))
	}
	got := []string{decision.Matches[0].Original, decision.Matches[1].Original, decision.Matches[2].Original}
	if strings.Join(got, ",") != "客户A,项目B,客户A" {
		t.Fatalf("命中顺序错误: %v", got)
	}
}

func TestEngineKeepsImmutableRuleSnapshot(t *testing.T) {
	rules := storage.RuleSet{
		Version: "1", DefaultAction: storage.DefaultAction,
		Rules: []storage.Rule{{
			ID: "keyword.block", Type: "keyword", Enabled: true,
			Action: ActionBlock, Keywords: []string{"客户A"},
		}},
	}
	engine, err := NewEngine(rules)
	if err != nil {
		t.Fatal(err)
	}
	rules.Rules[0].Enabled = false
	rules.Rules[0].Keywords[0] = "已被外部修改"
	decision := inspect(t, engine, mustPayload(t, `{"model":"gpt-test","input":"客户A"}`))
	if decision.Action != ActionBlock || len(decision.Matches) != 1 {
		t.Fatalf("规则快照被外部修改: %#v", decision)
	}
}

func TestEngineMaskIsOnePassAndNonCascading(t *testing.T) {
	engine := mustEngine(t, []storage.Rule{{
		ID: "keyword.mask", Type: "keyword_mapping", Enabled: true,
		Action: ActionMask, Mappings: []storage.Mapping{
			{Source: "内部系统A", Target: "生产数据库A"},
			{Source: "生产数据库A", Target: "测试数据库"},
		},
	}})
	payload := mustPayload(t, `{"model":"gpt-test","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"内部系统A连接生产数据库A"}]}]}`)
	decision := inspect(t, engine, payload)
	if err := engine.ApplyMask(payload, decision); err != nil {
		t.Fatal(err)
	}
	body, err := Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	if !strings.Contains(got, "生产数据库A连接测试数据库") {
		t.Fatalf("非级联替换结果错误: %s", got)
	}
}

func TestEngineDetectsOnlyValidPrivateIPv4(t *testing.T) {
	engine := mustEngine(t, []storage.Rule{{
		ID: "private-ip", Type: "private_ipv4", Enabled: true, Action: ActionWarn,
	}})
	payload := mustPayload(t, `{"model":"gpt-test","input":"host_10.1.2.3_prod 999.1.2.3 8.8.8.8 172.16.0.1 10.1.2.3.4"}`)
	decision := inspect(t, engine, payload)
	if len(decision.Matches) != 2 || decision.Action != ActionWarn {
		t.Fatalf("命中 = %#v，动作 = %s", decision.Matches, decision.Action)
	}
}

func TestExtractRejectsUnknownTextAndAttachments(t *testing.T) {
	tests := []string{
		`{"model":"gpt-test","future_text":"secret"}`,
		`{"model":"gpt-test","input":[{"type":"message","role":"user","future_text":"secret","content":"normal"}]}`,
		`{"model":"gpt-test","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"normal","future_text":"secret"}]}]}`,
		`{"model":"gpt-test","tools":[{"type":"function","name":"known","description":"normal","parameters":{"type":"object"},"future_text":"secret"}]}`,
		`{"model":"gpt-test","tools":[{"type":"future_tool","description":"secret"}]}`,
		`{"model":"gpt-test","input":[{"type":"input_image","image_url":"https://example.invalid/a.png"}]}`,
	}
	for _, body := range tests {
		if _, err := Extract([]byte(body)); err == nil {
			t.Fatalf("期望拒绝载荷: %s", body)
		}
	}
}

func TestExtractAllowsAttachmentNamedJSONSchemaProperties(t *testing.T) {
	body := `{
		"model":"gpt-test",
		"input":"normal",
		"tools":[{
			"type":"function",
			"name":"inspect_file",
			"description":"检查文件内容",
			"parameters":{
				"type":"object",
				"properties":{
					"file":{"type":"string","description":"客户A文件路径"},
					"image_url":{"type":"string","description":"图片地址"}
				},
				"required":["file"]
			}
		}],
		"text":{"format":{"type":"json_schema","schema":{"type":"object","properties":{"file":{"type":"string"}}}}}
	}`
	payload, err := Extract([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]Text, len(payload.Texts))
	for _, text := range payload.Texts {
		values[text.Value] = text
	}
	for _, expected := range []string{"inspect_file", "检查文件内容", "客户A文件路径", "图片地址"} {
		if _, exists := values[expected]; !exists {
			t.Errorf("未提取 JSON Schema 文本 %q", expected)
		}
	}
	if text, exists := values["file"]; !exists || text.Maskable {
		t.Fatalf("JSON Schema 属性名和 required 引用必须参与检测且不可脱敏: %#v", text)
	}
}

func TestEngineScansToolName(t *testing.T) {
	engine := mustEngine(t, []storage.Rule{{
		ID: "tool-name", Type: "keyword", Enabled: true, Action: ActionBlock, Keywords: []string{"客户A"},
	}})
	payload := mustPayload(t, `{"model":"gpt-test","input":"normal","tools":[{"type":"function","name":"query_客户A","description":"普通说明","parameters":{"type":"object","properties":{}}}]}`)
	decision := inspect(t, engine, payload)
	if decision.Action != ActionBlock || len(decision.Matches) != 1 || decision.Matches[0].Path != "/tools/0/name" {
		t.Fatalf("工具名称未被完整检测: %#v", decision)
	}
}

func TestExtractSupportsRegisteredCodexToolTypes(t *testing.T) {
	body := `{
		"model":"gpt-test",
		"input":"normal",
		"tools":[
			{"type":"custom","name":"apply_patch","description":"修改文件","format":{"type":"grammar","syntax":"lark","definition":"start: text"}},
			{"type":"tool_search","description":"搜索工具","execution":"client","parameters":{"type":"object","properties":{}}},
			{"type":"web_search","external_web_access":false}
		]
	}`
	if _, err := Extract([]byte(body)); err != nil {
		t.Fatal(err)
	}
}

func TestExtractPreservesTextOrderAndRejectsDuplicateKeys(t *testing.T) {
	payload := mustPayload(t, `{"instructions":"先出现","input":"后出现","model":"gpt-test"}`)
	if len(payload.Texts) != 3 || payload.Texts[0].Value != "先出现" || payload.Texts[1].Value != "后出现" || payload.Texts[2].Value != "gpt-test" {
		t.Fatalf("文本提取顺序错误: %#v", payload.Texts)
	}
	if _, err := Extract([]byte(`{"input":"one","input":"two"}`)); err == nil {
		t.Fatal("期望拒绝重复 JSON 键")
	}
	if _, err := Extract([]byte{'{', '"', 'i', 'n', 'p', 'u', 't', '"', ':', '"', 0xff, '"', '}'}); err == nil {
		t.Fatal("期望拒绝包含非法 UTF-8 的 JSON")
	}
}

func TestEngineScansProtocolStringFields(t *testing.T) {
	engine := mustEngine(t, []storage.Rule{{
		ID: "protocol-text", Type: "keyword", Enabled: true, Action: ActionBlock, Keywords: []string{"客户A"},
	}})
	payload := mustPayload(t, `{"model":"客户A-model","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"normal"}]}]}`)
	decision := inspect(t, engine, payload)
	if decision.Action != ActionBlock || len(decision.Matches) != 1 || decision.Matches[0].Path != "/model" {
		t.Fatalf("协议字符串字段未被完整检测: %#v", decision)
	}
}

func TestMaskRuleBlocksProtocolFieldsAndDynamicKeys(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		source string
		target string
		path   string
	}{
		{name: "模型名称", body: `{"model":"gpt-enterprise","input":"normal"}`, source: "gpt", target: "safe", path: "/model"},
		{name: "消息角色", body: `{"input":[{"type":"message","role":"user","content":"normal"}]}`, source: "user", target: "developer", path: "/input/0/role"},
		{name: "工具名称", body: `{"input":"normal","tools":[{"type":"function","name":"customer_lookup","description":"normal","parameters":{"type":"object","properties":{}}}]}`, source: "customer", target: "safe", path: "/tools/0/name"},
		{name: "元数据动态键", body: `{"input":"normal","metadata":{"客户A":"value"}}`, source: "客户A", target: "客户", path: "/metadata/客户A"},
		{name: "Schema 属性名", body: `{"input":"normal","tools":[{"type":"function","name":"lookup","description":"normal","parameters":{"type":"object","properties":{"客户A":{"type":"string"}},"required":["客户A"]}}]}`, source: "客户A", target: "客户", path: "/tools/0/parameters/properties/客户A"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine := mustEngine(t, []storage.Rule{{
				ID: "mask", Type: "keyword_mapping", Enabled: true, Action: ActionMask,
				Mappings: []storage.Mapping{{Source: test.source, Target: test.target}},
			}})
			payload := mustPayload(t, test.body)
			decision := inspect(t, engine, payload)
			if decision.Action != ActionBlock {
				t.Fatalf("不可脱敏字段未提升为阻断: %#v", decision)
			}
			found := false
			for _, match := range decision.Matches {
				if match.Path == test.path && match.Action == ActionBlock && !match.Maskable {
					found = true
				}
			}
			if !found {
				t.Fatalf("未找到不可脱敏命中 %s: %#v", test.path, decision.Matches)
			}
			before, err := Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			if err := engine.ApplyMask(payload, decision); err != nil {
				t.Fatal(err)
			}
			after, err := Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatalf("阻断决策修改了协议字段: before=%s after=%s", before, after)
			}
		})
	}
}

func TestInspectionCancellationAndMatchLimitFailClosed(t *testing.T) {
	engine := mustEngine(t, []storage.Rule{{
		ID: "single-character", Type: "keyword", Enabled: true, Action: ActionBlock, Keywords: []string{"a"},
	}})
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.Inspect(cancelled, Payload{Texts: []Text{{Path: "/input", Value: "a", Maskable: true}}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消未失败关闭: %v", err)
	}
	payload := Payload{Texts: []Text{{Path: "/input", Value: strings.Repeat("a", MaxMatchesPerInspection+1), Maskable: true}}}
	if _, err := engine.Inspect(context.Background(), payload); !errors.Is(err, ErrMatchLimitExceeded) {
		t.Fatalf("命中上限未失败关闭: %v", err)
	}
}

func TestActionPriority(t *testing.T) {
	engine := mustEngine(t, []storage.Rule{
		{ID: "warn", Type: "keyword", Enabled: true, Action: ActionWarn, Keywords: []string{"secret"}},
		{ID: "block", Type: "keyword", Enabled: true, Action: ActionBlock, Keywords: []string{"客户"}},
		{ID: "mask", Type: "keyword_mapping", Enabled: true, Action: ActionMask, Mappings: []storage.Mapping{{Source: "系统", Target: "业务"}}},
	})
	decision := inspect(t, engine, mustPayload(t, `{"model":"gpt-test","input":"secret 客户 系统"}`))
	if decision.Action != ActionBlock || len(decision.Matches) != 3 {
		t.Fatalf("决策错误: %#v", decision)
	}
}

func TestCaseInsensitiveRegexKeepsOriginalByteOffsets(t *testing.T) {
	engine := mustEngine(t, []storage.Rule{{
		ID: "regex", Type: "regex", Enabled: true, Action: ActionBlock,
		CaseSensitive: false, Pattern: "secret",
	}})
	decision := inspect(t, engine, mustPayload(t, `{"input":"前缀 SECRET 后缀"}`))
	if len(decision.Matches) != 1 || decision.Matches[0].Original != "SECRET" {
		t.Fatalf("正则原文区间错误: %#v", decision.Matches)
	}
}

func mustEngine(t *testing.T, rules []storage.Rule) *Engine {
	t.Helper()
	engine, err := NewEngine(storage.RuleSet{
		Version: "1", DefaultAction: storage.DefaultAction, Rules: rules,
	})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func inspect(t *testing.T, engine *Engine, payload Payload) Decision {
	t.Helper()
	decision, err := engine.Inspect(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

func mustPayload(t *testing.T, body string) Payload {
	t.Helper()
	payload, err := Extract([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
