package security

import (
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestNormalizedOriginalRanges(t *testing.T) {
	for _, test := range []struct {
		name, input, want, needle, original string
		caseSensitive                       bool
	}{
		{"ASCII 折叠", "prefix PROBE_92 suffix", "prefix probe_92 suffix", "probe_92", "PROBE_92", false},
		{"ASCII 保留大小写", "prefix PROBE_92 suffix", "prefix PROBE_92 suffix", "PROBE_92", "PROBE_92", true},
		{"全角", "前缀 ＡＢＣ 后缀", "前缀 abc 后缀", "abc", "ＡＢＣ", false},
		{"折叠展开", "前缀 Straße 后缀", "前缀 strasse 后缀", "ss", "ß", false},
		{"保留 Unicode 大小写", "前缀 Straße 后缀", "前缀 Straße 后缀", "Straße", "Straße", true},
		{"组合字符", "前缀 e\u0301 后缀", "前缀 é 后缀", "é", "e\u0301", false},
		{"兼容连字", "前缀 ﬃ 后缀", "前缀 ffi 后缀", "fi", "ﬃ", false},
		{"希腊折叠", "前缀 Σς 后缀", "前缀 σσ 后缀", "σσ", "Σς", false},
		{"长 ASCII 前缀", strings.Repeat("prefix_92 ", 4096) + "Straße", strings.Repeat("prefix_92 ", 4096) + "strasse", "strasse", "Straße", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := normalizeWithMapping(test.input, test.caseSensitive)
			if got.value != test.want {
				t.Fatalf("规范化文本错误: %q", got.value)
			}
			start := strings.Index(got.value, test.needle)
			left, right, ok := got.originalRange(start, start+len(test.needle))
			if !ok || left != strings.Index(test.input, test.original) || test.input[left:right] != test.original {
				t.Fatalf("原文区间错误: [%d,%d) 有效=%t", left, right, ok)
			}
		})
	}
}

func TestNormalizedRangeRejectsInvalidBounds(t *testing.T) {
	for _, input := range []string{"", "PROBE_92", "前缀 ＡＢＣ"} {
		normalized := normalizeWithMapping(input, false)
		for _, interval := range [][2]int{{-1, 1}, {0, 0}, {2, 1}, {0, len(normalized.value) + 1}} {
			if _, _, ok := normalized.originalRange(interval[0], interval[1]); ok {
				t.Fatalf("接受了无效区间: %v", interval)
			}
		}
	}
}

func TestNormalizedMaskRechecksReplacement(t *testing.T) {
	engine := mustEngine(t, []storage.Rule{
		{ID: "mask", Type: "keyword_mapping", Enabled: true, Action: ActionMask,
			Mappings: []storage.Mapping{{Source: "strasse", Target: "ＳＡＦＥ_92"}}},
		{ID: "block", Type: "keyword", Enabled: true, Action: ActionBlock, Keywords: []string{"safe_92"}},
	})
	payload := mustPayload(t, `{"input":"前缀 Straße 后缀"}`)
	decision := inspect(t, engine, payload)
	if decision.Action != ActionBlock || len(decision.Matches) != 2 || decision.Matches[1].Original != "ＳＡＦＥ_92" {
		t.Fatalf("未检查规范化后的替换结果: %+v", decision)
	}
	value, err := getString(payload.Root, "/input")
	if err != nil || value != "前缀 Straße 后缀" {
		t.Fatal("阻断请求不应修改原文", err)
	}
}

func FuzzNormalizeWithMapping(f *testing.F) {
	for _, input := range []string{
		"", "PROBE_92\x00\r\n", "中文 ＡＢＣ Straße e\u0301", "İΣςKﬃ",
		"a\u0315\u0300 가", "ﷺ", strings.Repeat("a\u0301", 40),
	} {
		f.Add(input, false)
		f.Add(input, true)
	}
	f.Fuzz(func(t *testing.T, input string, caseSensitive bool) {
		if len(input) > 512 || !utf8.ValidString(input) {
			t.Skip()
		}
		got := normalizeWithMapping(input, caseSensitive)
		want := referenceNormalizeWithMapping(input, caseSensitive)
		if got.value != want.value {
			t.Fatalf("规范化与原实现不一致: %q != %q", got.value, want.value)
		}
		// 每个字节的起止位置相同，即可保证任意连续匹配区间的端点相同。
		for index := range len(want.value) {
			left, right, ok := got.originalRange(index, index+1)
			span := want.spans[index]
			if !ok || left != span.start || right != span.end {
				t.Fatalf("第 %d 字节的原文映射与原实现不一致", index)
			}
		}
	})
}

// 保留优化前的算法作为差分测试参照，防止 Unicode 展开及原文映射发生变化。
func referenceNormalizeWithMapping(value string, caseSensitive bool) normalizedText {
	var iter norm.Iter
	iter.InitString(norm.NFKC, value)
	var builder strings.Builder
	folder := cases.Fold()
	spans := make([]sourceSpan, 0, len(value))
	for !iter.Done() {
		start := iter.Pos()
		segment := string(iter.Next())
		end := iter.Pos()
		if !caseSensitive {
			segment = folder.String(segment)
		}
		builder.WriteString(segment)
		for range len(segment) {
			spans = append(spans, sourceSpan{start: start, end: end})
		}
	}
	return normalizedText{value: builder.String(), spans: spans}
}
