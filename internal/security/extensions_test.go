package security

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestJSONExtensionsArePreservedAndInspected(t *testing.T) {
	for _, protocol := range []string{"responses", "chat"} {
		for _, location := range []string{"root", "history", "content", "tool", "new_type", "annotations", "logprobs"} {
			t.Run(protocol+"/"+location, func(t *testing.T) {
				for _, value := range []string{`null`, `{}`, `[]`, `{"type":"profile","tag":"probe_profile_93"}`, `{"nested":[{"text":"probe_extension_93","a/b~c":"probe_value_93"}],"flag":true,"count":9007199254740993}`} {
					body := extensionBody(protocol, location, value)
					payload, err := extensionExtract(protocol, []byte(body))
					if err != nil {
						t.Fatal("普通 JSON 扩展不应被字段白名单拒绝", err)
					}
					encoded, err := Marshal(payload)
					if err != nil {
						t.Fatal(err)
					}
					var before, after any
					for _, pair := range []struct {
						raw    []byte
						target *any
					}{{[]byte(body), &before}, {encoded, &after}} {
						decoder := json.NewDecoder(strings.NewReader(string(pair.raw)))
						decoder.UseNumber()
						if err := decoder.Decode(pair.target); err != nil {
							t.Fatal(err)
						}
					}
					if !reflect.DeepEqual(before, after) {
						t.Fatal("扩展字段丢失或数值精度改变")
					}
					if strings.Contains(value, "probe_extension_93") {
						foundValue, foundKey := false, false
						for _, text := range payload.Texts {
							if text.Value == "probe_extension_93" {
								foundValue = true
								if text.Maskable {
									t.Fatal("扩展对象中的 text 不应被当作正文替换")
								}
							}
							if text.Value == "a/b~c" && strings.HasSuffix(text.Path, "/a~1b~0c") && !text.Maskable {
								foundKey = true
							}
						}
						if !foundValue || !foundKey {
							t.Fatal("嵌套扩展的值或键名未完整检查")
						}
					}
				}
			})
		}
	}
}

func TestJSONExtensionsEnforceRulesOnKeysAndValues(t *testing.T) {
	for _, protocol := range []string{"responses", "chat"} {
		for _, location := range []string{"root", "history", "content", "tool", "new_type", "annotations", "logprobs"} {
			for _, key := range []bool{false, true} {
				for _, action := range []string{ActionBlock, ActionMask, ActionWarn} {
					t.Run(fmt.Sprintf("%s/%s/key=%t/%s", protocol, location, key, action), func(t *testing.T) {
						value := `{"nested":[{"text":"probe_denied_93"}]}`
						if key {
							value = `{"nested":[{"probe_denied_93":"normal"}]}`
						}
						payload, err := extensionExtract(protocol, []byte(extensionBody(protocol, location, value)))
						if err != nil {
							t.Fatal(err)
						}
						rule := storage.Rule{ID: "probe_rule_93", Type: "keyword", Enabled: true, Action: action, Keywords: []string{"probe_denied_93"}}
						if action == ActionMask {
							rule.Type, rule.Keywords = "keyword_mapping", nil
							rule.Mappings = []storage.Mapping{{Source: "probe_denied_93", Target: "probe_safe_93"}}
						}
						decision := inspect(t, mustEngine(t, []storage.Rule{rule}), payload)
						want := action
						if action == ActionMask {
							want = ActionBlock
						}
						if decision.Action != want || len(decision.Matches) != 1 {
							t.Fatal("扩展字段绕过规则或产生重复命中")
						}
						if action == ActionMask && decision.Matches[0].BlockReason != "unsafe_mask" {
							t.Fatal("扩展协议字段应保留不可安全替换的原因")
						}
					})
				}
			}
		}
	}
}

func TestJSONExtensionsCannotBypassAttachmentChecks(t *testing.T) {
	for _, protocol := range []string{"responses", "chat"} {
		for _, location := range []string{"root", "history", "content", "tool", "new_type"} {
			for _, value := range []string{`{"nested":{"file_data":"probe"}}`, `{"nested":{"type":"input_audio","data":"probe"}}`, `{"nested":{"image_url":"data:image/png;base64,cHJvYmU="}}`} {
				if _, err := extensionExtract(protocol, []byte(extensionBody(protocol, location, value))); err == nil {
					t.Fatal("扩展结构绕过附件限制")
				}
			}
		}
	}
	// 位置相同也不能用未知类型取得内嵌图片的扫描豁免。
	for _, typeName := range []string{"input_text", "future_content"} {
		body := fmt.Sprintf(`{"input":[{"role":"user","content":[{"type":%q,"image_url":"data:image/png;base64,cHJvYmU="}]}]}`, typeName)
		if _, err := Extract([]byte(body)); err == nil {
			t.Fatal("未验证的图片对象跳过文本检查")
		}
	}
}

func TestSeventeenthHistoryItemMetadata(t *testing.T) {
	for _, kind := range []string{"message", "reasoning", "function_call", "function_call_output", "custom_tool_call", "custom_tool_call_output", "future_history"} {
		items := make([]any, 16)
		for index := range items {
			items[index] = map[string]any{"role": "user", "content": "probe_history_93"}
		}
		items = append(items, map[string]any{"type": kind, "metadata": map[string]any{"nested": []any{map[string]any{"tag": "probe_metadata_93"}}}})
		raw, _ := json.Marshal(map[string]any{"input": items})
		payload, err := Extract(raw)
		if err != nil {
			t.Fatal("第 17 项 metadata 仍被拒绝", err)
		}
		found := false
		for _, text := range payload.Texts {
			if text.Path == "/input/16/metadata/nested/0/tag" && text.Value == "probe_metadata_93" {
				found = true
			}
		}
		if !found {
			t.Fatal("历史元数据未被递归检查")
		}
	}
}

func TestResponsesMixedHistoryExtensions(t *testing.T) {
	body := []byte(`{
		"input":[
			{"type":"reasoning","summary":[{"type":"summary_text","text":"probe_summary_93","metadata":{"future":["probe_summary_meta_93"]}}],"content":[{"type":"future_reasoning","text":"probe_reasoning_93"}],"metadata":{"phase":null}},
			{"type":"function_call","name":"probe_tool","call_id":"probe_call_93","arguments":"{}","metadata":{"future":{"value":"probe_call_meta_93"}}},
			{"type":"function_call_output","call_id":"probe_call_93","output":"probe_result_93","metadata":["probe_output_meta_93"]},
			{"type":"web_search_call","action":{"type":"search","queries":["probe_query_93"]},"metadata":{"status":"complete"}},
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"probe_answer_93","annotations":[{"type":"url_citation","url":"https://example.invalid/probe","title":"probe_title_93","start_index":0,"end_index":2}],"logprobs":[{"token":"probe_token_93","logprob":-1,"bytes":[112,114,111,98,101]}]}],"metadata":{"future":[]}},
			{"type":"message","role":"assistant","content":[{"type":"refusal","refusal":"probe_refusal_93"}]},
			{"type":"item_reference","id":"probe_item_93"}
		],
		"previous_response_id":"probe_response_93",
		"metadata":{"future":{"list":["probe_root_meta_93"]}},
		"tools":[{"type":"web_search","filters":{"allowed_domains":["example.invalid"]},"search_context_size":"medium"}],
		"tool_choice":{"type":"allowed_tools","mode":"auto","tools":[{"type":"function","name":"probe_tool"}]},
		"text":{"format":{"type":"json_object"}},
		"stream_options":{"future_option":{"text":"probe_stream_meta_93"}}
	}`)
	payload, err := Extract(body)
	if err != nil {
		t.Fatal("混合历史与扩展选项仍被逐类型白名单拒绝", err)
	}
	for _, expected := range []string{"probe_summary_meta_93", "probe_reasoning_93", "probe_call_meta_93", "probe_output_meta_93", "probe_query_93", "probe_title_93", "probe_token_93", "probe_refusal_93", "probe_response_93", "probe_root_meta_93", "probe_stream_meta_93"} {
		found := false
		for _, text := range payload.Texts {
			if text.Value == expected {
				found = true
			}
		}
		if !found {
			t.Fatalf("混合请求遗漏检查 %s", expected)
		}
	}
}

func FuzzJSONExtensionCoverage(f *testing.F) {
	f.Add("probe_key_93", "probe_value_93")
	f.Add("a/b~c", "中文扩展内容")
	f.Add("text", "probe_value_93")
	f.Fuzz(func(t *testing.T, key, value string) {
		if !utf8.ValidString(key) || !utf8.ValidString(value) {
			return
		}
		for _, protocol := range []string{"responses", "chat"} {
			extension, err := json.Marshal(map[string]any{key: []any{map[string]any{"text": value}}})
			if err != nil {
				t.Fatal(err)
			}
			payload, err := extensionExtract(protocol, []byte(extensionBody(protocol, "history", string(extension))))
			if err != nil {
				continue
			}
			keyFound, valueFound := false, false
			for _, text := range payload.Texts {
				if text.Value == key && !text.Maskable {
					keyFound = true
				}
				if text.Value == value && strings.HasSuffix(text.Path, "/0/text") && !text.Maskable {
					valueFound = true
				}
			}
			if !keyFound || !valueFound {
				t.Fatal("接受的 JSON 扩展存在未检查文本或错误的替换权限")
			}
		}
	})
}

func extensionExtract(protocol string, body []byte) (Payload, error) {
	if protocol == "chat" {
		return ExtractChatCompletions(body)
	}
	return Extract(body)
}

func extensionBody(protocol, location, value string) string {
	if protocol == "chat" {
		switch location {
		case "root":
			return `{"messages":[{"role":"user","content":"normal"}],"future_extension":` + value + `}`
		case "history":
			return `{"messages":[{"role":"assistant","content":"normal","metadata":` + value + `}]}`
		case "content":
			return `{"messages":[{"role":"user","content":[{"type":"text","text":"normal","future_extension":` + value + `}]}]}`
		case "new_type":
			return `{"messages":[{"role":"user","content":[{"type":"future_content","future_extension":` + value + `}]}]}`
		case "tool":
			return `{"messages":[{"role":"assistant","tool_calls":[{"id":"call_93","type":"function","function":{"name":"probe","arguments":"{}","future_extension":` + value + `}}]}]}`
		default:
			return `{"messages":[{"role":"assistant","content":"normal","` + location + `":` + value + `}]}`
		}
	}
	switch location {
	case "root":
		return `{"input":"normal","future_extension":` + value + `}`
	case "history":
		return `{"input":[{"role":"assistant","content":"normal","metadata":` + value + `}]}`
	case "content":
		return `{"input":[{"role":"user","content":[{"type":"input_text","text":"normal","future_extension":` + value + `}]}]}`
	case "new_type":
		return `{"input":[{"type":"future_history","content":` + value + `}]}`
	case "tool":
		return `{"input":"normal","tools":[{"type":"future_tool","description":"normal","future_extension":` + value + `}]}`
	case "annotations":
		return `{"input":[{"role":"assistant","content":[{"type":"output_text","text":"normal","annotations":[{"type":"url_citation","future_extension":` + value + `}]}]}]}`
	default:
		return `{"input":[{"role":"assistant","content":[{"type":"output_text","text":"normal","logprobs":[{"token":"probe_token_93","logprob":-1,"future_extension":` + value + `}]}]}]}`
	}
}
