package contract_test

import (
	"os"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/security"
)

func TestCodex0144SanitizedFixtureIsSupported(t *testing.T) {
	body, err := os.ReadFile("testdata/codex-0.144.5-responses.json")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := security.Extract(body)
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]bool)
	for _, text := range payload.Texts {
		values[text.Value] = true
	}
	for _, expected := range []string{
		"脱敏后的项目指令", "脱敏后的用户输入", "脱敏后的系统指令",
		"shell_command", "执行受控命令", "待执行命令",
		"apply_patch", "应用受控补丁", "搜索已登记工具",
	} {
		if !values[expected] {
			t.Errorf("未提取契约文本 %q", expected)
		}
	}
}
