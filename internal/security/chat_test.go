package security

import (
	"strings"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestChatScansMessagesToolCallsAndSchemas(t *testing.T) {
	body := `{"model":"gpt-test","messages":[{"role":"system","content":"系统指令"},{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"客户A"}}]},{"role":"tool","tool_call_id":"call_1","content":"工具结果"}],"tools":[{"type":"function","function":{"name":"lookup","description":"工具说明","parameters":{"type":"object","properties":{"file":{"type":"string","description":"文件说明"}},"required":["file"]}}}],"response_format":{"type":"json_schema","json_schema":{"name":"result","schema":{"type":"object","properties":{"image_url":{"type":"string"}}}}}}`
	payload, err := ExtractChatCompletions([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]bool)
	for _, text := range payload.Texts {
		values[text.Value] = true
	}
	for _, expected := range []string{"系统指令", "客户A", "工具结果", "工具说明", "file", "文件说明", "image_url"} {
		if !values[expected] {
			t.Errorf("未检测文本 %q", expected)
		}
	}
	engine := mustEngine(t, []storage.Rule{{ID: "customer", Type: "keyword", Action: ActionBlock, Enabled: true, Keywords: []string{"客户A"}}})
	if decision := inspect(t, engine, payload); decision.Action != ActionBlock {
		t.Fatalf("工具调用参数未触发阻断: %#v", decision)
	}
}

func TestChatMasksTextButBlocksProtocolFields(t *testing.T) {
	engine := mustEngine(t, []storage.Rule{{ID: "mask", Type: "keyword_mapping", Action: ActionMask, Enabled: true, Mappings: []storage.Mapping{{Source: "客户A", Target: "客户"}}}})
	for _, test := range []struct {
		body   string
		action string
	}{
		{`{"messages":[{"role":"user","content":[{"type":"text","text":"客户A"}]}]}`, ActionMask},
		{`{"messages":[{"role":"tool","tool_call_id":"1","content":"客户A"}]}`, ActionMask},
		{`{"messages":[{"role":"assistant","tool_calls":[{"id":"1","type":"function","function":{"name":"客户A","arguments":"{}"}}]}]}`, ActionBlock},
		{`{"messages":[{"role":"user","content":"正常"}],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"properties":{"客户A":{"type":"string"}}}}}]}`, ActionBlock},
	} {
		payload, err := ExtractChatCompletions([]byte(test.body))
		if err != nil {
			t.Fatal(err)
		}
		decision := inspect(t, engine, payload)
		if decision.Action != test.action {
			t.Fatalf("动作错误: got=%s want=%s body=%s", decision.Action, test.action, test.body)
		}
		if decision.Action == ActionMask {
			if err := engine.ApplyMask(payload, decision); err != nil {
				t.Fatal(err)
			}
			masked, _ := Marshal(payload)
			if strings.Contains(string(masked), "客户A") {
				t.Fatalf("消息未脱敏: %s", masked)
			}
		}
	}
}

func TestChatRejectsUnknownStructuresAndAttachments(t *testing.T) {
	for _, body := range []string{
		`{"messages":[]}`,
		`{"messages":[{"content":"secret"}]}`,
		`{"messages":[{"role":"user","content":"one","content":"two"}]}`,
		`{"messages":[{"role":"user","content":[{"type":"image_url","image_url":"https://example.invalid"}]}]}`,
		`{"messages":[{"role":"user","content":"normal"}],"input":"wrong protocol"}`,
	} {
		if _, err := ExtractChatCompletions([]byte(body)); err == nil {
			t.Errorf("期望拒绝载荷: %s", body)
		}
	}
	if _, err := Extract([]byte(`{"messages":[{"role":"user","content":"secret"}]}`)); err == nil {
		t.Fatal("Responses 不应接受 Chat Completions 载荷")
	}
}
