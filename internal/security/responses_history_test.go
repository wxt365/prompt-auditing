package security

import (
	"context"
	"strings"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestResponsesHistoryKeepsImagesAndMasksToolText(t *testing.T) {
	const image = "data:image/png;base64,YmluYXJ5"
	payload, err := Extract([]byte(`{"input":[
		{"type":"message","role":"user","content":[{"type":"input_text","text":"内部系统"},{"type":"input_image","image_url":"` + image + `","detail":"original"}]},
		{"type":"custom_tool_call","call_id":"call1","name":"apply_patch","input":"内部系统"},
		{"type":"custom_tool_call_output","call_id":"call1","output":"内部系统"},
		{"type":"function_call_output","call_id":"call2","output":[{"type":"input_text","text":"内部系统"},{"type":"input_image","image_url":"` + image + `","detail":"auto"}]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(storage.RuleSet{Version: "1", DefaultAction: storage.DefaultAction, Rules: []storage.Rule{
		{ID: "mask", Type: "keyword_mapping", Enabled: true, Action: "mask", Mappings: []storage.Mapping{{Source: "内部系统", Target: "业务系统"}}},
		{ID: "binary", Type: "keyword", Enabled: true, Action: "block", Keywords: []string{"YmluYXJ5"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := engine.Inspect(context.Background(), payload)
	if err != nil || decision.Action != ActionMask || len(decision.Matches) != 4 {
		t.Fatalf("文本提取或图片隔离失败: %#v %v", decision, err)
	}
	if err := engine.ApplyMask(payload, decision); err != nil {
		t.Fatal(err)
	}
	masked, err := Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(masked), "内部系统") || strings.Count(string(masked), "业务系统") != 4 || strings.Count(string(masked), image) != 2 {
		t.Fatalf("图片被修改或文本未脱敏: %s", masked)
	}
}

func TestResponsesImageValidationDoesNotAllowOtherAttachments(t *testing.T) {
	for _, body := range []string{
		`{"input":[{"type":"message","role":"user","content":[{"type":"input_image","image_url":"data:text/plain;base64,c2VjcmV0"}]}]}`,
		`{"input":[{"type":"message","role":"user","content":[{"type":"input_image","image_url":"data:image/png;base64,invalid!"}]}]}`,
		`{"input":[{"type":"message","role":"user","content":[{"type":"input_image","image_url":"file:///private.png"}]}]}`,
		`{"input":[{"type":"message","role":"user","content":[{"type":"input_audio","input_audio":{"data":"secret"}}]}]}`,
		`{"input":[{"type":"message","role":"user","content":[{"type":"input_file","file_data":"secret"}]}]}`,
	} {
		if _, err := Extract([]byte(body)); err == nil {
			t.Fatalf("不应放行未知结构或附件: %s", body)
		}
	}
}

func TestCustomToolHistoryStillBlocksAndProtectsProtocolNames(t *testing.T) {
	engine, err := NewEngine(storage.RuleSet{Version: "1", DefaultAction: storage.DefaultAction, Rules: []storage.Rule{
		{ID: "block", Type: "keyword", Enabled: true, Action: "block", Keywords: []string{"客户A"}},
		{ID: "name", Type: "keyword_mapping", Enabled: true, Action: "mask", Mappings: []storage.Mapping{{Source: "secret_tool", Target: "safe_tool"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"input":[{"type":"custom_tool_call","call_id":"1","name":"apply_patch","input":"客户A"}]}`,
		`{"input":[{"type":"custom_tool_call_output","call_id":"1","output":"客户A"}]}`,
		`{"input":[{"type":"custom_tool_call","call_id":"1","name":"secret_tool","input":"normal"}]}`,
	} {
		payload, err := Extract([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		decision, err := engine.Inspect(context.Background(), payload)
		if err != nil || decision.Action != ActionBlock {
			t.Fatalf("工具历史逃逸审计: %#v %v", decision, err)
		}
	}
}
