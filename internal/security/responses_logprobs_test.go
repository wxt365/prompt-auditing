package security

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func logprobsHistoryBody(value string) []byte {
	items := make([]string, 8)
	for index := range items {
		items[index] = `{"role":"user","content":"probe_history_92"}`
	}
	items = append(items, `{"type":"message","role":"assistant","content":[{"type":"output_text","text":"probe_text_92","annotations":[],"logprobs":`+value+`}]}`)
	return []byte(`{"input":[` + strings.Join(items, ",") + `]}`)
}

func TestResponsesHistoryLogprobsRoundTrip(t *testing.T) {
	for _, value := range []string{
		`null`, `[]`,
		`[{"token":"probe_token_92","logprob":-0.125,"top_logprobs":[]}]`,
		`[{"token":"probe_token_92","logprob":-1e-9,"top_logprobs":[{"token":"probe_alternative_92","logprob":-1.5}]}]`,
	} {
		t.Run(value, func(t *testing.T) {
			body := logprobsHistoryBody(value)
			payload, err := Extract(body)
			if err != nil {
				t.Fatal("带 logprobs 的历史消息不应被结构校验拒绝", err)
			}
			encoded, err := Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			var before, after any
			_ = json.Unmarshal(body, &before)
			_ = json.Unmarshal(encoded, &after)
			beforeJSON, _ := json.Marshal(before)
			afterJSON, _ := json.Marshal(after)
			if string(beforeJSON) != string(afterJSON) {
				t.Fatal("兼容处理不应删除或修改 logprobs")
			}
		})
	}
}

func TestResponsesHistoryLogprobsStillRejectsUnknownStructure(t *testing.T) {
	for _, value := range []string{
		`{}`, `"probe"`, `true`, `1`, `[null]`, `["probe"]`, `[{}]`,
		`[{"token":null,"logprob":-1}]`, `[{"token":"probe","logprob":"-1"}]`,
		`[{"token":"probe","logprob":-1,"top_logprobs":{}}]`,
		`[{"token":"probe","logprob":-1,"top_logprobs":[null]}]`,
	} {
		_, err := Extract(logprobsHistoryBody(value))
		if err == nil || !strings.Contains(err.Error(), "/input/8/content/0/logprobs") {
			t.Fatalf("应拒绝非法 logprobs 并保留字段路径: %v", err)
		}
	}
}

func TestResponsesLogprobsTokensRemainInspected(t *testing.T) {
	engine, err := NewEngine(storage.RuleSet{Version: "1", DefaultAction: storage.DefaultAction, Rules: []storage.Rule{
		{ID: "probe_mask_92", Type: "keyword_mapping", Action: ActionMask, Enabled: true, Mappings: []storage.Mapping{{Source: "probe_source_92", Target: "probe_safe_92"}}},
		{ID: "probe_block_92", Type: "keyword", Action: ActionBlock, Enabled: true, Keywords: []string{"probe_denied_92"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, location := range []string{"token", "alternative"} {
		for _, keyword := range []string{"probe_source_92", "probe_denied_92"} {
			t.Run(location+"/"+keyword, func(t *testing.T) {
				value := fmt.Sprintf(`[{"token":%q,"logprob":-1}]`, keyword)
				if location == "alternative" {
					value = fmt.Sprintf(`[{"token":"probe_normal_92","logprob":-1,"top_logprobs":[{"token":%q,"logprob":-2}]}]`, keyword)
				}
				payload, err := Extract(logprobsHistoryBody(value))
				if err != nil {
					t.Fatal(err)
				}
				decision, err := engine.Inspect(context.Background(), payload)
				if err != nil || decision.Action != ActionBlock || len(decision.Matches) != 1 || !strings.Contains(decision.Matches[0].Path, "/logprobs/") {
					t.Fatal("概率元数据中的文本未被安全审计", err)
				}
				if keyword == "probe_source_92" && decision.Matches[0].BlockReason != "unsafe_mask" {
					t.Fatal("概率元数据不可直接替换，应明确标记转为阻断")
				}
			})
		}
	}
}
