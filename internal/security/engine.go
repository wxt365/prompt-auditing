package security

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

var ipv4Candidate = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)

const MaxMatchesPerInspection = 10_000

var ErrMatchLimitExceeded = errors.New("安全检测命中数量超过上限")

type Engine struct {
	rules storage.RuleSet
}

func NewEngine(rules storage.RuleSet) (*Engine, error) {
	if err := storage.ValidateRuleSet(rules); err != nil {
		return nil, err
	}
	return &Engine{rules: cloneRuleSet(rules)}, nil
}

func cloneRuleSet(source storage.RuleSet) storage.RuleSet {
	result := storage.RuleSet{
		Version: source.Version, DefaultAction: source.DefaultAction,
		Rules: make([]storage.Rule, len(source.Rules)),
	}
	for index, rule := range source.Rules {
		result.Rules[index] = rule
		result.Rules[index].Keywords = append([]string(nil), rule.Keywords...)
		result.Rules[index].Mappings = append([]storage.Mapping(nil), rule.Mappings...)
	}
	return result
}

func (e *Engine) RuleSetVersion() string {
	return e.rules.Version
}

func (e *Engine) Inspect(ctx context.Context, payload Payload) (Decision, error) {
	decision := Decision{Action: e.rules.DefaultAction}
	for _, text := range payload.Texts {
		if err := ctx.Err(); err != nil {
			return Decision{}, err
		}
		var textMatches []Match
		// 先基于原文计算一次性替换，再对替换结果执行其他规则。
		// 这里只预演文本，阻断审计仍保留原请求，实际转发前才写入替换结果。
		checked := text
		for _, masking := range []bool{true, false} {
			var stageMatches []Match
			for _, rule := range e.rules.Rules {
				if !rule.Enabled || (rule.Action == ActionMask) != masking {
					continue
				}
				remaining := MaxMatchesPerInspection - len(decision.Matches) - len(textMatches) - len(stageMatches)
				matches, err := inspectRule(ctx, checked, rule, remaining)
				if err != nil {
					return Decision{}, err
				}
				stageMatches = append(stageMatches, matches...)
			}
			if masking && text.Maskable {
				// 审计与实际替换采用相同的重叠区间选择，未采用的替换不算命中。
				stageMatches = selectNonOverlapping(stageMatches)
				checked.Value = applyNonOverlapping(text.Value, stageMatches)
			}
			sortMatches(stageMatches)
			textMatches = append(textMatches, stageMatches...)
			for _, match := range stageMatches {
				if actionPriority(match.Action) > actionPriority(decision.Action) {
					decision.Action = match.Action
				}
			}
		}
		decision.Matches = append(decision.Matches, textMatches...)
	}
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	return decision, nil
}

func inspectRule(ctx context.Context, text Text, rule storage.Rule, limit int) ([]Match, error) {
	switch rule.Type {
	case "keyword":
		return inspectKeywords(ctx, text, rule, rule.Keywords, nil, limit)
	case "keyword_mapping":
		values := make([]string, 0, len(rule.Mappings))
		targets := make(map[string]string, len(rule.Mappings))
		for _, mapping := range rule.Mappings {
			values = append(values, mapping.Source)
			targets[mapping.Source] = mapping.Target
		}
		return inspectKeywords(ctx, text, rule, values, targets, limit)
	case "regex":
		return inspectRegex(ctx, text, rule, limit)
	case "private_ipv4":
		return inspectPrivateIPv4(ctx, text, rule, limit)
	default:
		return nil, nil
	}
}

func inspectKeywords(ctx context.Context, text Text, rule storage.Rule, values []string, targets map[string]string, limit int) ([]Match, error) {
	normalized := normalizeWithMapping(text.Value, rule.CaseSensitive)
	var matches []Match
	for _, keyword := range values {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		needle := normalizeRuleValue(keyword, rule.CaseSensitive)
		for offset := 0; offset <= len(normalized.value)-len(needle); {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			relative := strings.Index(normalized.value[offset:], needle)
			if relative < 0 {
				break
			}
			start := offset + relative
			end := start + len(needle)
			originalStart, originalEnd, ok := normalized.originalRange(start, end)
			if ok {
				if len(matches) >= limit {
					return nil, ErrMatchLimitExceeded
				}
				match := Match{
					RuleID: rule.ID, RuleName: rule.DisplayName(), Category: rule.Type, Path: text.Path,
					Start: originalStart, End: originalEnd, Original: text.Value[originalStart:originalEnd],
					Keyword: keyword, Target: targets[keyword], Action: rule.Action, Maskable: text.Maskable,
				}
				matches = append(matches, effectiveMatch(match))
			}
			offset = end
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return matches, nil
}

func inspectRegex(ctx context.Context, text Text, rule storage.Rule, limit int) ([]Match, error) {
	var matches []Match
	pattern := rule.Pattern
	if !rule.CaseSensitive {
		pattern = "(?i:" + pattern + ")"
	}
	expression := regexp.MustCompile(pattern)
	for offset := 0; offset <= len(text.Value); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		location := expression.FindStringSubmatchIndex(text.Value[offset:])
		if location == nil {
			break
		}
		for index := range location {
			if location[index] >= 0 {
				location[index] += offset
			}
		}
		if len(matches) >= limit {
			return nil, ErrMatchLimitExceeded
		}
		match := newMatch(text, rule, location[0], location[1], "")
		if rule.Action == ActionMask {
			match.Target = string(expression.ExpandString(nil, rule.Replacement, text.Value, location))
		}
		matches = append(matches, effectiveMatch(match))
		if location[1] > location[0] {
			offset = location[1]
		} else if location[1] == len(text.Value) {
			break
		} else {
			_, size := utf8.DecodeRuneInString(text.Value[location[1]:])
			offset = location[1] + size
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return matches, nil
}

func inspectPrivateIPv4(ctx context.Context, text Text, rule storage.Rule, limit int) ([]Match, error) {
	var matches []Match
	for offset := 0; offset < len(text.Value); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		location := ipv4Candidate.FindStringIndex(text.Value[offset:])
		if location == nil {
			break
		}
		start, end := offset+location[0], offset+location[1]
		offset = end
		if hasIPv4Continuation(text.Value, start, end) {
			continue
		}
		address, err := netip.ParseAddr(text.Value[start:end])
		if err == nil && address.Is4() && address.IsPrivate() {
			if len(matches) >= limit {
				return nil, ErrMatchLimitExceeded
			}
			matches = append(matches, effectiveMatch(newMatch(text, rule, start, end, text.Value[start:end])))
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return matches, nil
}

func effectiveMatch(match Match) Match {
	if match.Action == ActionMask && !match.Maskable {
		match.Action = ActionBlock
		match.BlockReason = "unsafe_mask"
	} else if match.Action == ActionBlock {
		match.BlockReason = "rule_block"
	}
	return match
}

func hasIPv4Continuation(value string, start, end int) bool {
	if start > 0 && isIPv4Character(value[start-1]) {
		return true
	}
	return end < len(value) && isIPv4Character(value[end])
}

func isIPv4Character(value byte) bool {
	return value == '.' || value >= '0' && value <= '9'
}

func newMatch(text Text, rule storage.Rule, start, end int, keyword string) Match {
	return Match{
		RuleID: rule.ID, RuleName: rule.DisplayName(), Category: rule.Type, Path: text.Path, Start: start, End: end,
		Original: text.Value[start:end], Keyword: keyword, Action: rule.Action, Maskable: text.Maskable,
	}
}

func (e *Engine) ApplyMask(payload Payload, decision Decision) error {
	if decision.Action != ActionMask {
		return nil
	}
	byPath := make(map[string][]Match)
	for _, match := range decision.Matches {
		if match.Action == ActionMask && match.Maskable {
			byPath[match.Path] = append(byPath[match.Path], match)
		}
	}
	for path, matches := range byPath {
		value, err := getString(payload.Root, path)
		if err != nil {
			return err
		}
		replacement := applyNonOverlapping(value, matches)
		if err := setString(payload.Root, path, replacement); err != nil {
			return err
		}
	}
	return nil
}

func applyNonOverlapping(value string, matches []Match) string {
	selected := selectNonOverlapping(matches)
	for index := len(selected) - 1; index >= 0; index-- {
		match := selected[index]
		value = value[:match.Start] + match.Target + value[match.End:]
	}
	return value
}

func sortMatches(matches []Match) {
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Start != matches[j].Start {
			return matches[i].Start < matches[j].Start
		}
		if matches[i].End != matches[j].End {
			return matches[i].End > matches[j].End
		}
		return matches[i].RuleID < matches[j].RuleID
	})
}

func selectNonOverlapping(matches []Match) []Match {
	sortMatches(matches)
	selected := make([]Match, 0, len(matches))
	lastEnd := -1
	for _, match := range matches {
		if match.Start >= lastEnd {
			selected = append(selected, match)
			lastEnd = match.End
		}
	}
	return selected
}

func getString(root any, pointer string) (string, error) {
	value, err := resolvePointer(root, pointer, false, "")
	if err != nil {
		return "", err
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("JSON Pointer %s 不是字符串", pointer)
	}
	return text, nil
}

func setString(root any, pointer, replacement string) error {
	_, err := resolvePointer(root, pointer, true, replacement)
	return err
}

func resolvePointer(root any, pointer string, set bool, replacement string) (any, error) {
	if pointer == "" {
		return nil, fmt.Errorf("不允许替换根节点")
	}
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	current := root
	for index, rawPart := range parts {
		part := strings.ReplaceAll(strings.ReplaceAll(rawPart, "~1", "/"), "~0", "~")
		last := index == len(parts)-1
		switch container := current.(type) {
		case map[string]any:
			child, exists := container[part]
			if !exists {
				return nil, fmt.Errorf("JSON Pointer 不存在: %s", pointer)
			}
			if last {
				if set {
					container[part] = replacement
				}
				return child, nil
			}
			current = child
		case []any:
			var arrayIndex int
			if _, err := fmt.Sscanf(part, "%d", &arrayIndex); err != nil || arrayIndex < 0 || arrayIndex >= len(container) {
				return nil, fmt.Errorf("JSON Pointer 数组下标无效: %s", pointer)
			}
			if last {
				child := container[arrayIndex]
				if set {
					container[arrayIndex] = replacement
				}
				return child, nil
			}
			current = container[arrayIndex]
		default:
			return nil, fmt.Errorf("JSON Pointer 无法继续解析: %s", pointer)
		}
	}
	return nil, fmt.Errorf("JSON Pointer 无效: %s", pointer)
}
