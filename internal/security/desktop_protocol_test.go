package security

import (
	"context"
	"strings"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestDesktopAdditionalToolsMasksNestedText(t *testing.T) {
	for _, location := range []string{"root", "history"} {
		t.Run(location, func(t *testing.T) {
			tools := `[{"type":"namespace","name":"functions","description":"内部系统","tools":[
				{"type":"namespace","name":"nested","tools":[{"type":"function","name":"probe","description":"内部系统",
				"parameters":{"type":"object","description":"内部系统","properties":{"image_url":{"type":"string","title":"内部系统"}}}}]}
			]}]`
			body := `{"reasoning":{"effort":"high","context":"auto"},"tools":` + tools + `}`
			if location == "history" {
				body = `{"reasoning":{"effort":"high","context":"auto"},"input":[{"type":"additional_tools","id":"tools_1","role":"developer","tools":` + tools + `}]}`
			}
			payload, err := Extract([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			engine, err := NewEngine(storage.RuleSet{Version: "1", DefaultAction: storage.DefaultAction, Rules: []storage.Rule{
				{ID: "mask", Type: "keyword_mapping", Enabled: true, Action: "mask", Mappings: []storage.Mapping{{Source: "内部系统", Target: "业务系统"}}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			decision, err := engine.Inspect(context.Background(), payload)
			if err != nil || decision.Action != ActionMask || len(decision.Matches) != 4 {
				t.Fatalf("嵌套工具文本未审计或错误阻断: %#v %v", decision, err)
			}
			if err := engine.ApplyMask(payload, decision); err != nil {
				t.Fatal(err)
			}
			masked, err := Marshal(payload)
			if err != nil || strings.Contains(string(masked), "内部系统") || strings.Count(string(masked), "业务系统") != 4 {
				t.Fatalf("嵌套工具脱敏失败: %s %v", masked, err)
			}
		})
	}
}

func TestDesktopAdditionalToolsProtectsSchemaKeysAndProtocol(t *testing.T) {
	engine, err := NewEngine(storage.RuleSet{Version: "1", DefaultAction: storage.DefaultAction, Rules: []storage.Rule{
		{ID: "mask", Type: "keyword_mapping", Enabled: true, Action: "mask", Mappings: []storage.Mapping{{Source: "sensitive", Target: "safe"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{
		`{"type":"function","name":"sensitive","parameters":{"type":"object"}}`,
		`{"type":"function","name":"probe","parameters":{"type":"object","properties":{"sensitive":{"type":"string"}}}}`,
		`{"type":"custom","name":"probe","format":{"type":"grammar","syntax":"lark","definition":"sensitive"}}`,
	} {
		payload, err := Extract([]byte(`{"input":[{"type":"additional_tools","tools":[{"type":"namespace","name":"functions","tools":[` + tool + `]}]}]}`))
		if err != nil {
			t.Fatal(err)
		}
		decision, err := engine.Inspect(context.Background(), payload)
		if err != nil || decision.Action != ActionBlock {
			t.Fatalf("工具协议或 Schema 动态键被忽略: %#v %v", decision, err)
		}
	}
}

func TestDesktopHistoryRetainsReasoningAndNamespace(t *testing.T) {
	body := `{"input":[
		{"type":"reasoning","id":"r1","encrypted_content":"opaque","summary":[],"content":[{"type":"reasoning_text","text":"normal"}],"internal_chat_message_metadata_passthrough":{"turn_id":"turn1"}},
		{"type":"function_call","namespace":"functions","name":"exec","call_id":"c1","arguments":"{}"},
		{"type":"function_call_output","name":"exec","namespace":"functions","call_id":"c1","output":"normal"},
		{"type":"message","role":"assistant","phase":"commentary","content":[{"type":"output_text","text":"normal"}]}
	]}`
	payload, err := Extract([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(payload.Texts) == 0 {
		t.Fatal("历史文本未参与审计")
	}
	for _, body := range []string{
		`{"reasoning":{"context":{}}}`,
		`{"input":[{"type":"additional_tools","tools":{}}]}`,
	} {
		if _, err := Extract([]byte(body)); err == nil {
			t.Fatal("不应放行无效或未知协议结构")
		}
	}
}
