package security

import (
	"strings"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

type sourceSpan struct {
	start int
	end   int
}

type normalizedText struct {
	value  string
	spans  []sourceSpan
	direct bool
}

func normalizeWithMapping(value string, caseSensitive bool) normalizedText {
	if isASCII(value) {
		// ASCII 规范化与大小写折叠均不改变字节位置，无需逐字节映射。
		if !caseSensitive {
			value = strings.ToLower(value)
		}
		return normalizedText{value: value, direct: true}
	}

	var iter norm.Iter
	iter.InitString(norm.NFKC, value)
	var builder strings.Builder
	builder.Grow(len(value))
	folder := cases.Fold()
	var folded [norm.MaxSegmentSize]byte
	spans := make([]sourceSpan, 0, len(value))
	for !iter.Done() {
		start := iter.Pos()
		segment := iter.Next()
		end := iter.Pos()
		if !caseSensitive {
			// 复用输出缓冲区，避免每个规范化片段都创建临时转换对象。
			n, consumed, err := folder.Transform(folded[:], segment, true)
			if err != nil || consumed != len(segment) {
				// 展开后的片段超过缓冲区时，退回原有转换方式以保留语义。
				segment = []byte(folder.String(string(segment)))
			} else {
				segment = folded[:n]
			}
		}
		builder.Write(segment)
		for range len(segment) {
			spans = append(spans, sourceSpan{start: start, end: end})
		}
	}
	return normalizedText{value: builder.String(), spans: spans}
}

func isASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func normalizeRuleValue(value string, caseSensitive bool) string {
	value = norm.NFKC.String(value)
	if !caseSensitive {
		value = cases.Fold().String(value)
	}
	return value
}

func (n normalizedText) originalRange(start, end int) (int, int, bool) {
	if start < 0 || end <= start || end > len(n.value) {
		return 0, 0, false
	}
	if n.direct {
		return start, end, true
	}
	return n.spans[start].start, n.spans[end-1].end, true
}
