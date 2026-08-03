package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const DefaultAction = "allow"

type PolicyStore struct {
	db *sql.DB
}

func OpenPolicy(ctx context.Context, path string) (*PolicyStore, error) {
	db, err := openDatabase(ctx, path, policyDatabase, false)
	if err != nil {
		return nil, err
	}
	return &PolicyStore{db: db}, nil
}

func (store *PolicyStore) Close() error {
	return store.db.Close()
}

func (store *PolicyStore) Load(ctx context.Context) (RuleSet, error) {
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return RuleSet{}, fmt.Errorf("开始规则快照事务: %w", err)
	}
	defer tx.Rollback()

	var version string
	if err := tx.QueryRowContext(ctx, "SELECT value FROM policy_meta WHERE key = 'rule_set_version'").Scan(&version); err != nil {
		return RuleSet{}, fmt.Errorf("读取规则集版本: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, type, action, enabled, case_sensitive,
		COALESCE(pattern, ''), COALESCE(replacement, '') FROM policy_rules ORDER BY id`)
	if err != nil {
		return RuleSet{}, err
	}
	defer rows.Close()

	set := RuleSet{Version: version, DefaultAction: DefaultAction}
	for rows.Next() {
		var rule Rule
		if err := rows.Scan(&rule.ID, &rule.Type, &rule.Action, &rule.Enabled, &rule.CaseSensitive, &rule.Pattern, &rule.Replacement); err != nil {
			return RuleSet{}, err
		}
		set.Rules = append(set.Rules, rule)
	}
	if err := rows.Err(); err != nil {
		return RuleSet{}, err
	}
	if err := rows.Close(); err != nil {
		return RuleSet{}, err
	}
	for index := range set.Rules {
		if err := loadRuleChildren(ctx, tx, &set.Rules[index]); err != nil {
			return RuleSet{}, err
		}
		if err := validateRule(set.Rules[index]); err != nil {
			return RuleSet{}, err
		}
	}
	if err := ValidateRuleSet(set); err != nil {
		return RuleSet{}, err
	}
	if err := tx.Commit(); err != nil {
		return RuleSet{}, fmt.Errorf("提交规则快照事务: %w", err)
	}
	return set, nil
}

func loadRuleChildren(ctx context.Context, tx *sql.Tx, rule *Rule) error {
	keywordRows, err := tx.QueryContext(ctx, "SELECT keyword FROM policy_keywords WHERE rule_id = ? ORDER BY sort_order", rule.ID)
	if err != nil {
		return err
	}
	for keywordRows.Next() {
		var keyword string
		if err := keywordRows.Scan(&keyword); err != nil {
			keywordRows.Close()
			return err
		}
		rule.Keywords = append(rule.Keywords, keyword)
	}
	if err := keywordRows.Close(); err != nil {
		return err
	}

	mappingRows, err := tx.QueryContext(ctx, "SELECT source, target FROM policy_mappings WHERE rule_id = ? ORDER BY sort_order", rule.ID)
	if err != nil {
		return err
	}
	defer mappingRows.Close()
	for mappingRows.Next() {
		var mapping Mapping
		if err := mappingRows.Scan(&mapping.Source, &mapping.Target); err != nil {
			return err
		}
		rule.Mappings = append(rule.Mappings, mapping)
	}
	return mappingRows.Err()
}

func (store *PolicyStore) AddBlock(ctx context.Context, id string, keywords []string, caseSensitive bool) error {
	if len(keywords) == 0 {
		return errors.New("至少需要一个拦截关键字")
	}
	for _, keyword := range keywords {
		if strings.TrimSpace(keyword) == "" {
			return errors.New("拦截关键字不能为空")
		}
	}
	return store.insertRule(ctx, Rule{ID: id, Type: "keyword", Action: "block", Enabled: true, CaseSensitive: caseSensitive, Keywords: keywords})
}

func (store *PolicyStore) AddReplacement(ctx context.Context, id string, mappings []Mapping, caseSensitive bool) error {
	if len(mappings) == 0 {
		return errors.New("至少需要一组替换映射")
	}
	for _, mapping := range mappings {
		if strings.TrimSpace(mapping.Source) == "" || mapping.Target == "" {
			return errors.New("替换映射的 source 和 target 均不能为空")
		}
	}
	return store.insertRule(ctx, Rule{ID: id, Type: "keyword_mapping", Action: "mask", Enabled: true, CaseSensitive: caseSensitive, Mappings: mappings})
}

func (store *PolicyStore) AddRegex(ctx context.Context, id, action, pattern, replacement string, caseSensitive bool) error {
	rule := Rule{
		ID: id, Type: "regex", Action: action, Enabled: true, CaseSensitive: caseSensitive,
		Pattern: pattern, Replacement: replacement,
	}
	if err := validateRule(rule); err != nil {
		return err
	}
	return store.insertRule(ctx, rule)
}

func (store *PolicyStore) AddPrivateIPv4(ctx context.Context, id, action string) error {
	rule := Rule{ID: id, Type: "private_ipv4", Action: action, Enabled: true}
	if err := validateRule(rule); err != nil {
		return err
	}
	return store.insertRule(ctx, rule)
}

func (store *PolicyStore) insertRule(ctx context.Context, rule Rule) error {
	if err := validateRule(rule); err != nil {
		return err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO policy_rules
		(id, type, action, enabled, case_sensitive, pattern, replacement, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?)`,
		rule.ID, rule.Type, rule.Action, rule.Enabled, rule.CaseSensitive, rule.Pattern, rule.Replacement, now, now); err != nil {
		return fmt.Errorf("写入规则 %s: %w", rule.ID, err)
	}
	for index, keyword := range uniqueStrings(rule.Keywords) {
		if _, err := tx.ExecContext(ctx, "INSERT INTO policy_keywords(rule_id, keyword, sort_order) VALUES(?, ?, ?)", rule.ID, keyword, index); err != nil {
			return fmt.Errorf("写入规则关键字: %w", err)
		}
	}
	for index, mapping := range rule.Mappings {
		key := normalizedSourceKey(mapping.Source, rule.CaseSensitive)
		if _, err := tx.ExecContext(ctx, `INSERT INTO policy_mappings(rule_id, source, source_key, target, sort_order)
			VALUES(?, ?, ?, ?, ?)`, rule.ID, mapping.Source, key, mapping.Target, index); err != nil {
			return fmt.Errorf("写入替换映射: %w", err)
		}
	}
	if err := incrementRuleSetVersion(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *PolicyStore) SetEnabled(ctx context.Context, id string, enabled bool) error {
	return store.mutateRule(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, "UPDATE policy_rules SET enabled = ?, updated_at = ? WHERE id = ?", enabled, time.Now().UTC().Format(time.RFC3339Nano), id)
		if err != nil {
			return err
		}
		return requireOneAffected(result, id)
	})
}

func (store *PolicyStore) Delete(ctx context.Context, id string) error {
	return store.mutateRule(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, "DELETE FROM policy_rules WHERE id = ?", id)
		if err != nil {
			return err
		}
		return requireOneAffected(result, id)
	})
}

func (store *PolicyStore) mutateRule(ctx context.Context, operation func(*sql.Tx) error) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := operation(tx); err != nil {
		return err
	}
	if err := incrementRuleSetVersion(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func incrementRuleSetVersion(ctx context.Context, tx *sql.Tx) error {
	result, err := tx.ExecContext(ctx, `UPDATE policy_meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)
		WHERE key = 'rule_set_version'`)
	if err != nil {
		return err
	}
	return requireOneAffected(result, "rule_set_version")
}

func requireOneAffected(result sql.Result, id string) error {
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("未找到记录 %s", id)
	}
	return nil
}

func validateRule(rule Rule) error {
	if strings.TrimSpace(rule.ID) == "" {
		return errors.New("规则 ID 不能为空")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`).MatchString(rule.ID) {
		return fmt.Errorf("规则 ID 格式无效: %s", rule.ID)
	}
	if !isAction(rule.Action) {
		return fmt.Errorf("规则 %s 的 action 无效: %s", rule.ID, rule.Action)
	}
	switch rule.Type {
	case "keyword":
		if len(rule.Keywords) == 0 || rule.Action == "mask" {
			return fmt.Errorf("关键字规则 %s 配置无效", rule.ID)
		}
		if duplicate := duplicateNormalized(rule.Keywords, rule.CaseSensitive); duplicate != "" {
			return fmt.Errorf("关键字规则 %s 包含重复关键字 %q", rule.ID, duplicate)
		}
	case "keyword_mapping":
		if rule.Action != "mask" || len(rule.Mappings) == 0 {
			return fmt.Errorf("替换规则 %s 配置无效", rule.ID)
		}
		seen := make(map[string]struct{}, len(rule.Mappings))
		for _, mapping := range rule.Mappings {
			if strings.TrimSpace(mapping.Source) == "" || mapping.Target == "" {
				return fmt.Errorf("替换规则 %s 包含空 source 或 target", rule.ID)
			}
			key := normalizedSourceKey(mapping.Source, rule.CaseSensitive)
			if _, exists := seen[key]; exists {
				return fmt.Errorf("替换规则 %s 包含重复 source %q", rule.ID, mapping.Source)
			}
			seen[key] = struct{}{}
		}
	case "regex":
		if rule.Pattern == "" {
			return fmt.Errorf("正则规则 %s 缺少 pattern", rule.ID)
		}
		pattern := rule.Pattern
		if !rule.CaseSensitive {
			pattern = "(?i:" + pattern + ")"
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("正则规则 %s 无效: %w", rule.ID, err)
		}
		if rule.Action == "mask" && rule.Replacement == "" {
			return fmt.Errorf("正则替换规则 %s 缺少 replacement", rule.ID)
		}
	case "private_ipv4":
		if rule.Action == "mask" {
			return fmt.Errorf("私网 IPv4 规则 %s 不支持 mask", rule.ID)
		}
	default:
		return fmt.Errorf("规则 %s 的 type 无效: %s", rule.ID, rule.Type)
	}
	return nil
}

func ValidateRuleSet(set RuleSet) error {
	if set.DefaultAction != DefaultAction {
		return fmt.Errorf("默认动作必须为 %s", DefaultAction)
	}
	version, err := ParseVersion(set.Version)
	if err != nil || version < 1 {
		return fmt.Errorf("规则集版本无效: %q", set.Version)
	}
	ids := make(map[string]struct{}, len(set.Rules))
	mappingTargets := make(map[string]string)
	for _, rule := range set.Rules {
		if _, exists := ids[rule.ID]; exists {
			return fmt.Errorf("规则 ID 重复: %s", rule.ID)
		}
		ids[rule.ID] = struct{}{}
		if err := validateRule(rule); err != nil {
			return err
		}
		for _, mapping := range rule.Mappings {
			key := normalizedSourceKey(mapping.Source, rule.CaseSensitive)
			if target, exists := mappingTargets[key]; exists && target != mapping.Target {
				return fmt.Errorf("源关键字 %q 对应多个目标字", mapping.Source)
			}
			if _, exists := mappingTargets[key]; exists {
				return fmt.Errorf("源关键字重复: %q", mapping.Source)
			}
			mappingTargets[key] = mapping.Target
		}
	}
	return nil
}

func isAction(action string) bool {
	switch action {
	case "allow", "warn", "mask", "block":
		return true
	default:
		return false
	}
}

func normalizedSourceKey(source string, _ bool) string {
	return cases.Fold().String(norm.NFKC.String(source))
}

func duplicateNormalized(values []string, caseSensitive bool) string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		key := norm.NFKC.String(value)
		if !caseSensitive {
			key = cases.Fold().String(key)
		}
		if _, exists := seen[key]; exists {
			return value
		}
		seen[key] = struct{}{}
	}
	return ""
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func SortRules(rules []Rule) {
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
}

func ParseVersion(value string) (int64, error) {
	return strconv.ParseInt(value, 10, 64)
}
