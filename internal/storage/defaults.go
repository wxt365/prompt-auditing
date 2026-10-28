package storage

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
)

// 默认规则随程序打包，仅在首次创建规则库时写入。
//
//go:embed defaults.json
var bundledRulesJSON []byte

func seedBundledRules(ctx context.Context, db *sql.DB) error {
	var rules []Rule
	if err := json.Unmarshal(bundledRulesJSON, &rules); err != nil {
		return fmt.Errorf("读取内置默认规则: %w", err)
	}
	if err := ValidateRuleSet(RuleSet{Version: "1", DefaultAction: DefaultAction, Rules: rules}); err != nil {
		return fmt.Errorf("校验内置默认规则: %w", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, rule := range rules {
		if err := insertRuleTx(ctx, tx, rule); err != nil {
			return err
		}
	}
	return tx.Commit()
}
