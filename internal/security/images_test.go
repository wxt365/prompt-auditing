package security

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestImageJSONInspectionAndMaskPermissions(t *testing.T) {
	engine, err := NewEngine(storage.RuleSet{Version: "1", DefaultAction: ActionAllow, Rules: []storage.Rule{
		{ID: "mask", Type: "keyword_mapping", Action: ActionMask, Enabled: true, Mappings: []storage.Mapping{{Source: "内部系统A", Target: "业务系统"}}},
		{ID: "block", Type: "keyword", Action: ActionBlock, Enabled: true, Keywords: []string{"客户A"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, body, action string
		edit               bool
	}{
		{"生成提示词", `{"prompt":"内部系统A","model":"gpt-test","stream":true}`, ActionMask, false},
		{"编辑提示词", `{"prompt":"内部系统A","images":[{"file_id":"file-1"}],"mask":{"image_url":"https://example.com/mask.png"}}`, ActionMask, true},
		{"模型名不可替换", `{"prompt":"ok","model":"内部系统A"}`, ActionBlock, false},
		{"文件ID不可替换", `{"prompt":"ok","images":[{"file_id":"内部系统A"}]}`, ActionBlock, true},
		{"图片URL不可替换", `{"prompt":"ok","images":[{"image_url":"https://example.com/内部系统A.png"}]}`, ActionBlock, true},
		{"动态键检测", `{"prompt":"ok","metadata":{"客户A":"value"}}`, ActionBlock, false},
		{"扩展值检测", `{"prompt":"ok","future":{"note":"客户A"}}`, ActionBlock, false},
		{"扩展提示词不可替换", `{"prompt":"ok","future":{"prompt":"内部系统A"}}`, ActionBlock, false},
		{"同名键值检测", `{"prompt":"ok","metadata":{"内部系统A":"内部系统A"}}`, ActionBlock, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			extract := ExtractImageGeneration
			if test.edit {
				extract = ExtractImageEdit
			}
			payload, err := extract([]byte(test.body))
			if err != nil {
				t.Fatal(err)
			}
			decision, err := engine.Inspect(context.Background(), payload)
			if err != nil || decision.Action != test.action {
				t.Fatalf("decision=%+v err=%v", decision, err)
			}
			if test.action == ActionMask {
				if err := engine.ApplyMask(payload, decision); err != nil {
					t.Fatal(err)
				}
				if payload.Root.(map[string]any)["prompt"] != "业务系统" {
					t.Fatal("提示词未替换")
				}
			}
		})
	}
}

func TestImageJSONRejectsInvalidStructure(t *testing.T) {
	for _, body := range []string{
		`{}`, `{"prompt":null}`, `{"prompt":" "}`, `{"prompt":[]}`,
		`{"prompt":"ok","prompt":"other"}`, `{"prompt":"ok","stream":"true"}`,
		`{"prompt":"ok","model":123}`, `{"prompt":"ok","images":[]}`,
		`{"prompt":"ok","images":["https://example.com/i.png"]}`,
		`{"prompt":"ok","images":[{"image_url":"ftp://example.com/i.png"}]}`,
		`{"prompt":"ok","images":[{"image_url":"https://user:pass@example.com/i.png"}]}`,
		`{"prompt":"ok","images":[{"image_url":"data:image/png;base64,%%%"}]}`,
		`{"prompt":"ok","images":[{"file_id":""}]}`,
		`{"prompt":"ok","images":[{"file_id":"x","image_url":"https://example.com/i.png"}]}`,
		`{"prompt":"ok","images":[{}]}`,
		`{"prompt":"ok","images":[{"file_id":"x"}],"mask":null}`,
		`{"prompt":"ok","images":[{"file_id":"x"}],"future":{"image_url":"data:image/png;base64,YQ=="}}`,
		`{"prompt":"ok","images":[{"file_id":"x"}],"input":[{"content":[{"type":"input_image","image_url":"data:image/png;base64,YQ=="}]}]}`,
	} {
		if _, err := ExtractImageEdit([]byte(body)); err == nil {
			t.Errorf("无效请求被接受: %s", body)
		}
	}
	tooMany := `{"prompt":"ok","images":[` + strings.Repeat(`{"file_id":"x"},`, 16) + `{"file_id":"x"}]}`
	if _, err := ExtractImageEdit([]byte(tooMany)); err == nil {
		t.Fatal("接受超过 16 张图片")
	}
	if _, err := ExtractImageGeneration([]byte(`{"prompt":"ok","image":"opaque"}`)); err == nil {
		t.Fatal("生成接口不应接受未登记附件")
	}
}

func TestImageJSONOnlyExemptsRegisteredBinary(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("客户A"))
	body := `{"prompt":"ok","images":[{"image_url":"data:image/png;base64,` + encoded + `"}],"markup":{"file_id":"file-1"}}`
	payload, err := ExtractImageEdit([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range payload.Texts {
		if strings.Contains(text.Value, encoded) {
			t.Fatal("已登记的图片二进制不应作为文本检测")
		}
	}
	serialized, err := Marshal(payload)
	if err != nil || !strings.Contains(string(serialized), encoded) {
		t.Fatal("图片二进制丢失")
	}
	// 新的图片引用权限不得影响原有 Responses / Chat 附件限制。
	if _, err := ExtractChatCompletions([]byte(`{"messages":[{"role":"user","content":"ok"}],"images":[{"file_id":"file-1"}]}`)); err == nil {
		t.Fatal("Chat 附件限制被放松")
	}
	if _, err := Extract([]byte(`{"input":"ok","images":[{"file_id":"file-1"}]}`)); err == nil {
		t.Fatal("Responses 附件限制被放松")
	}
}
