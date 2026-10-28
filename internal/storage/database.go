package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/xiaotaowang/prompt-auditing/internal/platform"
	_ "modernc.org/sqlite"
)

const schemaVersion = 3

type databaseKind string

const (
	policyDatabase databaseKind = "policy"
	auditDatabase  databaseKind = "audit"
)

func InitDatabases(ctx context.Context, policyPath, auditPath string) error {
	if filepath.Clean(policyPath) == filepath.Clean(auditPath) {
		return errors.New("policy.db 和 audit.db 必须使用不同文件")
	}
	for _, path := range []string{policyPath, auditPath} {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("数据库已存在，拒绝覆盖: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("检查数据库文件 %s: %w", path, err)
		}
	}

	created := make([]string, 0, 2)
	cleanup := func() {
		for _, path := range created {
			for _, suffix := range []string{"", "-wal", "-shm"} {
				_ = os.Remove(path + suffix)
			}
		}
	}
	for _, item := range []struct {
		path string
		kind databaseKind
	}{{policyPath, policyDatabase}, {auditPath, auditDatabase}} {
		if err := createEmptyFile(item.path); err != nil {
			cleanup()
			return err
		}
		created = append(created, item.path)
		db, err := openDatabase(ctx, item.path, item.kind, true)
		if err != nil {
			cleanup()
			return err
		}
		if item.kind == policyDatabase {
			if err := seedBundledRules(ctx, db); err != nil {
				_ = db.Close()
				cleanup()
				return fmt.Errorf("初始化默认规则: %w", err)
			}
		}
		if err := db.Close(); err != nil {
			cleanup()
			return fmt.Errorf("关闭数据库 %s: %w", item.path, err)
		}
	}
	return nil
}

func createEmptyFile(path string) error {
	directory := filepath.Dir(path)
	if err := platform.SecureDir(directory); err != nil {
		return fmt.Errorf("保护数据库目录 %s: %w", directory, err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("创建数据库 %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("关闭新数据库 %s: %w", path, err)
	}
	if err := platform.SecureFile(path); err != nil {
		return fmt.Errorf("保护数据库 %s: %w", path, err)
	}
	return nil
}

func openDatabase(ctx context.Context, path string, kind databaseKind, initialize bool) (*sql.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("数据库不存在 %s: %w", path, err)
	}
	if err := platform.ValidateSecureDir(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("数据库目录权限校验失败: %w", err)
	}
	if err := platform.ValidateSecureFile(path); err != nil {
		return nil, fmt.Errorf("数据库文件权限校验失败: %w", err)
	}
	if err := validateExistingSidecars(path); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		return nil, fmt.Errorf("打开 SQLite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	closeWithError := func(err error) (*sql.DB, error) {
		_ = db.Close()
		return nil, err
	}
	if !initialize {
		if _, err := readMigrationVersion(ctx, db); err != nil {
			return closeWithError(fmt.Errorf("数据库未初始化或迁移状态无效 %s: %w", path, err))
		}
	}
	if err := configureDatabase(ctx, db, initialize); err != nil {
		return closeWithError(fmt.Errorf("配置 SQLite %s: %w", path, err))
	}
	if err := secureSQLiteSidecars(path); err != nil {
		return closeWithError(err)
	}
	if !initialize {
		if err := verifyDatabase(ctx, db, kind); err != nil {
			return closeWithError(fmt.Errorf("迁移前校验 SQLite %s: %w", path, err))
		}
	}
	if err := migrateDatabase(ctx, db, kind); err != nil {
		return closeWithError(fmt.Errorf("迁移 SQLite %s: %w", path, err))
	}
	if err := secureSQLiteSidecars(path); err != nil {
		return closeWithError(err)
	}
	if err := verifyDatabase(ctx, db, kind); err != nil {
		return closeWithError(fmt.Errorf("校验 SQLite %s: %w", path, err))
	}
	return db, nil
}

func verifyMigrationState(ctx context.Context, db *sql.DB) error {
	version, err := readMigrationVersion(ctx, db)
	if err != nil {
		return err
	}
	if version != schemaVersion {
		return errors.New("数据库需要先由网关启动过程升级")
	}
	return nil
}

func readMigrationVersion(ctx context.Context, db *sql.DB) (int, error) {
	var migrationTable int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'").Scan(&migrationTable); err != nil {
		return 0, err
	}
	if migrationTable != 1 {
		return 0, errors.New("缺少 schema_migrations，必须先执行 init")
	}
	var current, migrations int
	if err := db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0), COUNT(*) FROM schema_migrations").Scan(&current, &migrations); err != nil {
		return 0, err
	}
	if current > schemaVersion {
		return 0, fmt.Errorf("数据库版本 %d 高于程序支持版本 %d", current, schemaVersion)
	}
	if current < 1 || migrations != current {
		return 0, fmt.Errorf("数据库迁移状态无效: current=%d count=%d", current, migrations)
	}
	return current, nil
}

func sqliteDSN(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		absolute = path
	}
	uriPath := filepath.ToSlash(absolute)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	return (&url.URL{Scheme: "file", Path: uriPath}).String()
}

func configureDatabase(ctx context.Context, db *sql.DB, initialize bool) error {
	if initialize {
		if _, err := db.ExecContext(ctx, "PRAGMA auto_vacuum = INCREMENTAL"); err != nil {
			return err
		}
	}
	for _, statement := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = FULL",
		"PRAGMA busy_timeout = 5000",
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("执行 %s: %w", statement, err)
		}
	}
	return nil
}

func verifyDatabase(ctx context.Context, db *sql.DB, kind databaseKind) error {
	var integrity string
	if err := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
		return err
	}
	if !strings.EqualFold(integrity, "ok") {
		return fmt.Errorf("integrity_check 返回 %q", integrity)
	}
	checks := []struct {
		query string
		want  int
		name  string
	}{
		{"PRAGMA foreign_keys", 1, "foreign_keys"},
		{"PRAGMA synchronous", 2, "synchronous"},
		{"PRAGMA busy_timeout", 5000, "busy_timeout"},
	}
	for _, check := range checks {
		var got int
		if err := db.QueryRowContext(ctx, check.query).Scan(&got); err != nil {
			return err
		}
		if got != check.want {
			return fmt.Errorf("%s=%d，期望 %d", check.name, got, check.want)
		}
	}
	var journalMode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return err
	}
	if !strings.EqualFold(journalMode, "wal") {
		return fmt.Errorf("journal_mode=%q，期望 WAL", journalMode)
	}
	rows, err := db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	if rows.Next() {
		rows.Close()
		return errors.New("foreign_key_check 发现违规数据")
	}
	if err := rows.Close(); err != nil {
		return err
	}
	return verifySchema(ctx, db, kind)
}

func verifySchema(ctx context.Context, db *sql.DB, kind databaseKind) error {
	var current, migrations int
	if err := db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0), COUNT(*) FROM schema_migrations").Scan(&current, &migrations); err != nil {
		return err
	}
	if current < 1 || current > schemaVersion || migrations != current {
		return fmt.Errorf("数据库迁移状态无效: current=%d count=%d", current, migrations)
	}
	required := map[databaseKind]map[string][]string{
		policyDatabase: {"table": {"schema_migrations", "policy_meta", "policy_rules", "policy_keywords", "policy_mappings"}},
		auditDatabase: {
			"table": {"schema_migrations", "audit_events", "audit_matches"},
			"index": {"idx_audit_events_occurred_at", "idx_audit_events_request_id", "idx_audit_events_action_result", "idx_audit_matches_keyword", "idx_audit_matches_rule_id"},
		},
	}
	for objectType, names := range required[kind] {
		for _, name := range names {
			var count int
			if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type = ? AND name = ?", objectType, name).Scan(&count); err != nil {
				return err
			}
			if count != 1 {
				return fmt.Errorf("缺少必需的 %s: %s", objectType, name)
			}
		}
	}
	if current >= 2 {
		columnQuery := "SELECT name FROM policy_rules LIMIT 0"
		if kind == auditDatabase {
			columnQuery = "SELECT rule_name FROM audit_matches LIMIT 0"
		}
		rows, err := db.QueryContext(ctx, columnQuery)
		if err != nil {
			return fmt.Errorf("规则名称字段缺失: %w", err)
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	if kind == auditDatabase {
		if current >= 3 {
			rows, err := db.QueryContext(ctx, "SELECT action, reason FROM audit_matches LIMIT 0")
			if err != nil {
				return fmt.Errorf("命中处置字段缺失: %w", err)
			}
			if err := rows.Close(); err != nil {
				return err
			}
		}
		expectedIndexes := map[string][]string{
			"idx_audit_events_occurred_at":   {"occurred_at"},
			"idx_audit_events_request_id":    {"request_id"},
			"idx_audit_events_action_result": {"action", "result"},
			"idx_audit_matches_keyword":      {"matched_keyword"},
			"idx_audit_matches_rule_id":      {"rule_id"},
		}
		for name, columns := range expectedIndexes {
			if err := verifyIndexColumns(ctx, db, name, columns); err != nil {
				return err
			}
		}
	}
	return nil
}

func verifyIndexColumns(ctx context.Context, db *sql.DB, name string, expected []string) error {
	rows, err := db.QueryContext(ctx, fmt.Sprintf("PRAGMA index_info(%q)", name))
	if err != nil {
		return fmt.Errorf("读取索引 %s: %w", name, err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var sequence, columnID int
		var column string
		if err := rows.Scan(&sequence, &columnID, &column); err != nil {
			return fmt.Errorf("读取索引 %s 列: %w", name, err)
		}
		columns = append(columns, column)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !slices.Equal(columns, expected) {
		return fmt.Errorf("索引 %s 列无效: got=%v want=%v", name, columns, expected)
	}
	return nil
}

func validateExistingSidecars(path string) error {
	for _, suffix := range []string{"-wal", "-shm"} {
		candidate := path + suffix
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return fmt.Errorf("读取 SQLite 辅助文件 %s: %w", candidate, err)
		}
		if err := platform.ValidateSecureFile(candidate); err != nil {
			return fmt.Errorf("SQLite 辅助文件权限过宽 %s: %w", candidate, err)
		}
	}
	return nil
}

func secureSQLiteSidecars(path string) error {
	for _, suffix := range []string{"-wal", "-shm"} {
		candidate := path + suffix
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return fmt.Errorf("读取 SQLite 辅助文件 %s: %w", candidate, err)
		}
		if err := platform.SecureFile(candidate); err != nil {
			return fmt.Errorf("保护 SQLite 辅助文件 %s: %w", candidate, err)
		}
	}
	return nil
}

func migrateDatabase(ctx context.Context, db *sql.DB, kind databaseKind) error {
	var migrationTable int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'").Scan(&migrationTable); err != nil {
		return err
	}
	current := 0
	if migrationTable == 1 {
		if err := db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&current); err != nil {
			return err
		}
	}
	if current > schemaVersion {
		return fmt.Errorf("数据库版本 %d 高于程序支持版本 %d", current, schemaVersion)
	}
	if current == schemaVersion {
		return nil
	}
	if current != 0 && current != 1 && current != 2 {
		return fmt.Errorf("不支持从数据库版本 %d 迁移", current)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statements := []string{}
	if current == 0 {
		statements = append(statements, `CREATE TABLE schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`)
		if kind == policyDatabase {
			statements = append(statements, policyMigrationV1...)
		} else {
			statements = append(statements, auditMigrationV1...)
		}
		statements = append(statements, "INSERT INTO schema_migrations(version, applied_at) VALUES(1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))")
	}
	if current < 2 {
		if kind == policyDatabase {
			statements = append(statements, "ALTER TABLE policy_rules ADD COLUMN name TEXT NOT NULL DEFAULT ''",
				`UPDATE policy_rules SET name = CASE id WHEN 'credential.openai-api-key' THEN 'API 密钥检测' WHEN 'credential.password-assignment' THEN '密码检测' WHEN 'network.private-ipv4' THEN '私网 IPv4 检测' ELSE id END`)
		} else {
			statements = append(statements, "ALTER TABLE audit_matches ADD COLUMN rule_name TEXT NOT NULL DEFAULT ''")
		}
		statements = append(statements, "INSERT INTO schema_migrations(version, applied_at) VALUES(2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))")
	}
	if kind == auditDatabase {
		statements = append(statements, "ALTER TABLE audit_matches ADD COLUMN action TEXT NOT NULL DEFAULT ''",
			"ALTER TABLE audit_matches ADD COLUMN reason TEXT NOT NULL DEFAULT ''")
	}
	statements = append(statements, "INSERT INTO schema_migrations(version, applied_at) VALUES(3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))")
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("执行迁移: %w", err)
		}
	}
	return tx.Commit()
}

var policyMigrationV1 = []string{
	`CREATE TABLE policy_meta (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`,
	`INSERT INTO policy_meta(key, value) VALUES('rule_set_version', '1')`,
	`CREATE TABLE policy_rules (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL,
		action TEXT NOT NULL,
		enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
		case_sensitive INTEGER NOT NULL CHECK(case_sensitive IN (0, 1)),
		pattern TEXT,
		replacement TEXT,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`,
	`CREATE TABLE policy_keywords (
		rule_id TEXT NOT NULL REFERENCES policy_rules(id) ON DELETE CASCADE,
		keyword TEXT NOT NULL,
		sort_order INTEGER NOT NULL,
		PRIMARY KEY(rule_id, keyword)
	)`,
	`CREATE TABLE policy_mappings (
		rule_id TEXT NOT NULL REFERENCES policy_rules(id) ON DELETE CASCADE,
		source TEXT NOT NULL,
		source_key TEXT NOT NULL UNIQUE,
		target TEXT NOT NULL,
		sort_order INTEGER NOT NULL,
		PRIMARY KEY(rule_id, source)
	)`,
	`INSERT INTO policy_rules(id, type, action, enabled, case_sensitive, pattern, replacement, created_at, updated_at)
		VALUES('credential.openai-api-key', 'regex', 'block', 1, 1, '\bsk-[A-Za-z0-9_-]{20,}\b', NULL,
		strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))`,
	`INSERT INTO policy_rules(id, type, action, enabled, case_sensitive, pattern, replacement, created_at, updated_at)
		VALUES('credential.password-assignment', 'regex', 'block', 1, 0, '(?:password|passwd|pwd)\s*[:=]\s*[^\s,;]{4,}', NULL,
		strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))`,
	`INSERT INTO policy_rules(id, type, action, enabled, case_sensitive, pattern, replacement, created_at, updated_at)
		VALUES('network.private-ipv4', 'private_ipv4', 'warn', 0, 0, NULL, NULL,
		strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))`,
}

var auditMigrationV1 = []string{
	`CREATE TABLE audit_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		request_id TEXT NOT NULL,
		event_type TEXT NOT NULL,
		occurred_at TEXT NOT NULL,
		user_name TEXT NOT NULL,
		rule_set_version TEXT NOT NULL,
		action TEXT NOT NULL,
		result TEXT NOT NULL,
		match_count INTEGER NOT NULL,
		request_body_json TEXT,
		request_hmac_sha256 TEXT,
		upstream_status INTEGER,
		duration_ms INTEGER NOT NULL,
		error_code TEXT
	)`,
	`CREATE TABLE audit_matches (
		event_id INTEGER NOT NULL REFERENCES audit_events(id) ON DELETE CASCADE,
		ordinal INTEGER NOT NULL,
		rule_id TEXT NOT NULL,
		category TEXT NOT NULL,
		matched_keyword TEXT,
		PRIMARY KEY(event_id, ordinal)
	)`,
	`CREATE INDEX idx_audit_events_occurred_at ON audit_events(occurred_at)`,
	`CREATE INDEX idx_audit_events_request_id ON audit_events(request_id)`,
	`CREATE INDEX idx_audit_events_action_result ON audit_events(action, result)`,
	`CREATE INDEX idx_audit_matches_keyword ON audit_matches(matched_keyword)`,
	`CREATE INDEX idx_audit_matches_rule_id ON audit_matches(rule_id)`,
}
