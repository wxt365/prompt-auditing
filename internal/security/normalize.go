package security

import (
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

type sourceSpan struct {
	start int
	end   int
}

type normalizedText struct {
	value string
	spans []sourceSpan
}

func normalizeWithMapping(value string, caseSensitive bool) normalizedText {
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

func normalizeRuleValue(value string, caseSensitive bool) string {
	value = norm.NFKC.String(value)
	if !caseSensitive {
		value = cases.Fold().String(value)
	}
	return value
}

func (n normalizedText) originalRange(start, end int) (int, int, bool) {
	if start < 0 || end <= start || end > len(n.spans) {
		return 0, 0, false
	}
	return n.spans[start].start, n.spans[end-1].end, true
}
