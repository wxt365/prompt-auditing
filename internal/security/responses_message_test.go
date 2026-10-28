package security

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestResponsesMessageWithoutTypeIsInspectedAndMasked(t *testing.T) {
	engine, err := NewEngine(storage.RuleSet{Version: "1", DefaultAction: storage.DefaultAction, Rules: []storage.Rule{
		{ID: "mask", Type: "keyword_mapping", Action: "mask", Enabled: true, Mappings: []storage.Mapping{{Source: "stage_source_7f3", Target: "stage_safe_7f3"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"system", "developer", "user", "assistant"} {
		for _, array := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/array=%t", role, array), func(t *testing.T) {
				var content any = "stage_source_7f3"
				if array {
					content = []any{map[string]any{"type": "input_text", "text": content}}
				}
				original := map[string]any{"input": []any{map[string]any{"role": role, "content": content}}}
				raw, _ := json.Marshal(original)
				payload, err := Extract(raw)
				if err != nil {
					t.Fatal(err)
				}
				decision, err := engine.Inspect(context.Background(), payload)
				if err != nil || decision.Action != ActionMask || len(decision.Matches) != 1 {
					t.Fatal("省略 type 的消息未参与规则检测")
				}
				if err := engine.ApplyMask(payload, decision); err != nil {
					t.Fatal(err)
				}
				message := payload.Root.(map[string]any)["input"].([]any)[0].(map[string]any)
				if _, exists := message["type"]; exists {
					t.Fatal("兼容校验不应给上游请求补写 type")
				}
				var text any = message["content"]
				if array {
					text = text.([]any)[0].(map[string]any)["text"]
				}
				if text != "stage_safe_7f3" {
					t.Fatal("省略 type 的消息未执行替换")
				}
			})
		}
	}
}

func TestResponsesMessageWithoutTypeStillRejectsUnknownStructure(t *testing.T) {
	for _, item := range []string{
		`{}`, `{"content":"normal"}`, `{"role":"user"}`, `{"role":"user","content":null}`,
		`{"role":null,"content":"normal"}`, `{"role":"tool","content":"normal"}`,
		`{"role":"user","content":42}`, `{"role":"user","content":{}}`,
		`{"role":"user","content":"normal","type":null}`,
		`{"role":"user","content":"normal","type":42}`,
		`{"role":"user","content":"normal","type":""}`,
		`{"role":"user","content":[{"type":"input_audio","input_audio":{}}]}`,
		`{"role":"user","content":[{"type":"input_file","file_data":"normal"}]}`,
		`{"call_id":"c1","output":"normal"}`,
	} {
		if _, err := Extract([]byte(`{"input":[` + item + `]}`)); err == nil {
			t.Fatal("省略 type 时放行了无效消息、未知结构或附件")
		}
	}
}
