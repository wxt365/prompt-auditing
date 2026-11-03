package security

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestChatImagesPreserveDataAndMaskOnlyText(t *testing.T) {
	engine := mustEngine(t, []storage.Rule{
		{ID: "mask", Type: "keyword_mapping", Action: ActionMask, Enabled: true, Mappings: []storage.Mapping{{Source: "内部系统", Target: "业务系统"}}},
		{ID: "binary", Type: "keyword", Action: ActionBlock, Enabled: true, Keywords: []string{"YmluYXJ5"}},
	})
	for _, imageURL := range []string{
		"https://example.com/image.png", "http://example.com/image.png",
		"data:image/png;base64,YmluYXJ5", "data:image/jpeg;base64,YmluYXJ5",
		"data:image/webp;base64,YmluYXJ5", "data:image/gif;base64,YmluYXJ5",
	} {
		for _, detail := range []string{"", "auto", "low", "high", "original"} {
			t.Run(imageURL+"/"+detail, func(t *testing.T) {
				option := ""
				if detail != "" {
					option = fmt.Sprintf(`,"detail":%q`, detail)
				}
				body := fmt.Sprintf(`{"model":"gpt-test","messages":[{"role":"user","content":[{"type":"text","text":"内部系统"},{"type":"image_url","image_url":{"url":%q%s}},{"type":"image_url","image_url":{"url":%q}}]}],"stream":true}`, imageURL, option, imageURL)
				payload, err := ExtractChatCompletions([]byte(body))
				if err != nil {
					t.Fatal(err)
				}
				decision := inspect(t, engine, payload)
				if decision.Action != ActionMask || len(decision.Matches) != 1 {
					t.Fatalf("图片二进制参与扫描或文本未脱敏: %+v", decision)
				}
				if err := engine.ApplyMask(payload, decision); err != nil {
					t.Fatal(err)
				}
				masked, err := Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				var expected, actual any
				if err := json.Unmarshal([]byte(strings.ReplaceAll(body, "内部系统", "业务系统")), &expected); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(masked, &actual); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(expected, actual) {
					t.Fatalf("图片或协议字段被修改: %s", masked)
				}
			})
		}
	}
}

func TestChatImageURLsAndExtensionsRemainInspected(t *testing.T) {
	for _, part := range []string{
		`{"type":"image_url","image_url":{"url":"https://example.com/probe_chat_93.png"}}`,
		`{"type":"image_url","image_url":{"url":"data:image/png;base64,YmluYXJ5","future":{"text":"probe_chat_93"}}}`,
		`{"type":"image_url","image_url":{"url":"data:image/png;base64,YmluYXJ5","probe_chat_93":"normal"}}`,
		`{"type":"image_url","image_url":{"url":"data:image/png;base64,YmluYXJ5"},"future":{"text":"probe_chat_93"}}`,
		`{"type":"image_url","image_url":{"url":"data:image/png;base64,YmluYXJ5"},"future":"data:image/png;base64,cHJvYmVfY2hhdF85Mw== probe_chat_93"}`,
	} {
		for _, action := range []string{ActionBlock, ActionMask, ActionWarn} {
			t.Run(part+"/"+action, func(t *testing.T) {
				body := `{"messages":[{"role":"user","content":[` + part + `]}]}`
				payload, err := ExtractChatCompletions([]byte(body))
				if err != nil {
					t.Fatal(err)
				}
				rule := storage.Rule{ID: "probe", Type: "keyword", Action: action, Enabled: true, Keywords: []string{"probe_chat_93"}}
				want := action
				if action == ActionMask {
					rule.Type, rule.Keywords = "keyword_mapping", nil
					rule.Mappings = []storage.Mapping{{Source: "probe_chat_93", Target: "safe"}}
					want = ActionBlock
				}
				decision := inspect(t, mustEngine(t, []storage.Rule{rule}), payload)
				if decision.Action != want || len(decision.Matches) != 1 || decision.Matches[0].Maskable {
					t.Fatalf("图片地址、键名或扩展字段绕过检查: %+v", decision)
				}
			})
		}
	}
	// 相同 data URL 出现在扩展字段时，不能继承图片数据的扫描豁免。
	payload, err := ExtractChatCompletions([]byte(`{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,YmluYXJ5"},"future":"data:image/png;base64,YmluYXJ5"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	engine := mustEngine(t, []storage.Rule{{ID: "binary", Type: "keyword", Action: ActionBlock, Enabled: true, Keywords: []string{"YmluYXJ5"}}})
	decision := inspect(t, engine, payload)
	if decision.Action != ActionBlock || len(decision.Matches) != 1 || decision.Matches[0].Path != "/messages/0/content/0/future" {
		t.Fatalf("扩展字段错误继承图片豁免: %+v", decision)
	}
}

func TestChatImagesKeepProtocolFieldsUnmaskable(t *testing.T) {
	payload, err := ExtractChatCompletions([]byte(`{"model":"gpt-test","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,YmluYXJ5","detail":"original"}}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"gpt-test", "user", "image_url", "original"} {
		engine := mustEngine(t, []storage.Rule{{ID: "mask", Type: "keyword_mapping", Action: ActionMask, Enabled: true, Mappings: []storage.Mapping{{Source: source, Target: "safe"}}}})
		decision := inspect(t, engine, payload)
		if decision.Action != ActionBlock || len(decision.Matches) == 0 {
			t.Fatalf("图片消息的协议字段被允许替换: source=%s decision=%+v", source, decision)
		}
	}
}

func TestChatImagesRejectInvalidStructuresAndAttachmentBypasses(t *testing.T) {
	for _, part := range []string{
		`{"type":"image_url"}`,
		`{"type":"image_url","image_url":null}`,
		`{"type":"image_url","image_url":"https://example.com/image.png"}`,
		`{"type":"image_url","image_url":{}}`,
		`{"type":"image_url","image_url":{"url":12}}`,
		`{"type":"image_url","image_url":{"url":""}}`,
		`{"type":"image_url","image_url":{"url":"file:///private/image.png"}}`,
		`{"type":"image_url","image_url":{"url":"https://user:pass@example.com/image.png"}}`,
		`{"type":"image_url","image_url":{"url":"data:text/plain;base64,YmluYXJ5"}}`,
		`{"type":"image_url","image_url":{"url":"data:image/png;base64,invalid!"}}`,
		`{"type":"image_url","image_url":{"url":"https://example.com/image.png","detail":"invalid"}}`,
		`{"type":"image_url","image_url":{"url":"https://example.com/image.png","detail":null}}`,
		`{"type":"text","image_url":{"url":"data:image/png;base64,YmluYXJ5"}}`,
		`{"type":"future_content","image_url":{"url":"data:image/png;base64,YmluYXJ5"}}`,
		`{"image_url":{"url":"data:image/png;base64,YmluYXJ5"}}`,
		`{"type":"input_image","image_url":"data:image/png;base64,YmluYXJ5"}`,
		`{"type":"image_url","image_url":{"url":"https://example.com/image.png","url":"https://example.com/other.png"}}`,
		`{"type":"text","future":{"type":"image_url","image_url":{"url":"data:image/png;base64,YmluYXJ5"}}}`,
		`{"type":"image_url","image_url":{"url":"data:image/png;base64,YmluYXJ5","future":{"image_url":{"url":"data:image/png;base64,YmluYXJ5"}}}}`,
		`{"type":"input_audio","input_audio":{"data":"YmluYXJ5"}}`,
		`{"type":"file","file":{"file_data":"YmluYXJ5"}}`,
	} {
		body := `{"messages":[{"role":"user","content":[` + part + `]}]}`
		if _, err := ExtractChatCompletions([]byte(body)); err == nil {
			t.Fatalf("不应接受无效图片或其他附件: %s", body)
		}
	}
	for _, body := range []string{
		`{"messages":[{"role":"user","content":"normal","image_url":{"url":"data:image/png;base64,YmluYXJ5"}}]}`,
		`{"messages":[{"role":"user","content":"normal"}],"metadata":{"type":"image_url","image_url":{"url":"data:image/png;base64,YmluYXJ5"}}}`,
		`{"messages":[{"role":"user","content":"normal"}],"future":{"messages":[{"content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,YmluYXJ5"}}]}]}}`,
	} {
		if _, err := ExtractChatCompletions([]byte(body)); err == nil {
			t.Fatalf("非正文路径取得图片豁免: %s", body)
		}
	}
}
