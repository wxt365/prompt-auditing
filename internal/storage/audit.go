package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/audit"
)

type AuditStore struct {
	db            *sql.DB
	path          string
	retentionDays int
	maxBytes      int64
	cleanupMu     sync.Mutex
	healthy       atomic.Bool
	now           func() time.Time
}

func OpenAudit(ctx context.Context, path string, retentionDays int, maxBytes int64) (*AuditStore, error) {
	if retentionDays <= 0 || maxBytes <= 0 {
		return nil, errors.New("审计保留天数和大小上限必须大于零")
	}
	db, err := openDatabase(ctx, path, auditDatabase, false)
	if err != nil {
		return nil, err
	}
	store := &AuditStore{db: db, path: path, retentionDays: retentionDays, maxBytes: maxBytes, now: time.Now}
	store.healthy.Store(true)
	if err := store.Cleanup(ctx); err != nil {
		store.healthy.Store(false)
		db.Close()
		return nil, err
	}
	return store, nil
}

func CheckAudit(ctx context.Context, path string) error {
	db, err := openDatabase(ctx, path, auditDatabase, false)
	if err != nil {
		return err
	}
	return db.Close()
}

func (store *AuditStore) Close() error {
	store.healthy.Store(false)
	return store.db.Close()
}

func (store *AuditStore) Healthy() bool {
	return store.healthy.Load()
}

func (store *AuditStore) MarkUnhealthy() {
	store.healthy.Store(false)
}

func (store *AuditStore) Fingerprint([]byte) string {
	return ""
}

func (store *AuditStore) Write(event audit.Event) error {
	return store.WriteEvent(context.Background(), event)
}

func (store *AuditStore) WriteEvent(ctx context.Context, event audit.Event) error {
	if !store.Healthy() {
		return errors.New("审计数据库不可用")
	}
	if event.RequestID == "" || event.EventType == "" || event.User == "" || event.RuleSetVersion == "" || event.Action == "" || event.Result == "" {
		return errors.New("审计事件缺少必填字段")
	}
	if event.SchemaVersion == 0 {
		event.SchemaVersion = 1
	}
	if event.SchemaVersion != 1 {
		return fmt.Errorf("不支持的审计 Schema 版本 %d", event.SchemaVersion)
	}
	if event.OccurredAt == "" {
		event.OccurredAt = store.now().UTC().Format(time.RFC3339Nano)
	} else {
		occurredAt, err := time.Parse(time.RFC3339Nano, event.OccurredAt)
		if err != nil {
			return fmt.Errorf("审计时间无效: %w", err)
		}
		event.OccurredAt = occurredAt.UTC().Format(time.RFC3339Nano)
	}
	if len(event.RequestBody) > 0 && !json.Valid(event.RequestBody) {
		return errors.New("审计请求体不是有效 JSON")
	}
	if event.EventType == "decision" && event.Action == "block" && len(event.RequestBody) == 0 {
		return errors.New("阻断决策必须包含完整 JSON 请求体")
	}
	if event.Action != "block" && len(event.RequestBody) > 0 {
		return errors.New("非阻断事件不得记录完整请求体")
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var requestBody any
	if len(event.RequestBody) > 0 {
		requestBody = string(event.RequestBody)
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO audit_events
		(request_id, event_type, occurred_at, user_name, rule_set_version, action, result,
		 match_count, request_body_json, request_hmac_sha256, upstream_status, duration_ms, error_code)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?, NULLIF(?, ''))`,
		event.RequestID, event.EventType, event.OccurredAt, event.User, event.RuleSetVersion,
		event.Action, event.Result, event.MatchCount, requestBody, event.RequestHMAC,
		event.UpstreamStatus, event.DurationMS, event.ErrorCode,
	)
	if err != nil {
		return fmt.Errorf("写入审计事件: %w", err)
	}
	eventID, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("读取审计事件 ID: %w", err)
	}
	for index, match := range uniqueAuditMatches(event.Matches) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_matches
			(event_id, ordinal, rule_id, category, matched_keyword) VALUES(?, ?, ?, ?, NULLIF(?, ''))`,
			eventID, index, match.RuleID, match.Category, match.MatchedKeyword); err != nil {
			return fmt.Errorf("写入审计命中明细: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交审计事务: %w", err)
	}
	if err := secureSQLiteSidecars(store.path); err != nil {
		store.MarkUnhealthy()
		return err
	}
	return nil
}

func uniqueAuditMatches(matches []audit.Match) []audit.Match {
	seen := make(map[string]struct{}, len(matches))
	result := make([]audit.Match, 0, len(matches))
	for _, match := range matches {
		key := match.RuleID + "\x00" + match.Category + "\x00" + match.MatchedKeyword
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, match)
	}
	return result
}

func (store *AuditStore) RunMaintenance(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			maintenanceCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			err := store.Cleanup(maintenanceCtx)
			cancel()
			if err != nil {
				store.MarkUnhealthy()
				return
			}
		}
	}
}

func (store *AuditStore) Cleanup(ctx context.Context) error {
	store.cleanupMu.Lock()
	defer store.cleanupMu.Unlock()
	cutoff := store.now().UTC().AddDate(0, 0, -store.retentionDays).Format(time.RFC3339Nano)
	if _, err := store.db.ExecContext(ctx, "DELETE FROM audit_events WHERE occurred_at < ?", cutoff); err != nil {
		return fmt.Errorf("清理过期审计: %w", err)
	}
	if err := store.enforceMaxBytes(ctx); err != nil {
		return err
	}
	if _, err := store.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("执行 WAL checkpoint: %w", err)
	}
	if _, err := store.db.ExecContext(ctx, "PRAGMA incremental_vacuum"); err != nil {
		return fmt.Errorf("回收审计空间: %w", err)
	}
	if _, err := store.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("完成审计空间回收 checkpoint: %w", err)
	}
	return secureSQLiteSidecars(store.path)
}

func (store *AuditStore) enforceMaxBytes(ctx context.Context) error {
	for {
		size, err := sqliteFilesSize(store.path)
		if err != nil {
			return err
		}
		if size <= store.maxBytes {
			return nil
		}
		result, err := store.db.ExecContext(ctx, `DELETE FROM audit_events WHERE id IN (
			SELECT id FROM audit_events ORDER BY occurred_at, id LIMIT 1000
		)`)
		if err != nil {
			return fmt.Errorf("按容量清理审计: %w", err)
		}
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if count == 0 {
			return fmt.Errorf("审计数据库大小 %d 超过限制 %d，且无可清理事件", size, store.maxBytes)
		}
		if _, err := store.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			return err
		}
		if _, err := store.db.ExecContext(ctx, "PRAGMA incremental_vacuum"); err != nil {
			return err
		}
		if _, err := store.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			return err
		}
	}
}

func sqliteFilesSize(path string) (int64, error) {
	var total int64
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("读取数据库大小 %s: %w", candidate, err)
		}
		total += info.Size()
	}
	return total, nil
}

type BlockedAuditRecord struct {
	RequestID       string
	OccurredAt      string
	MatchedKeywords []string
	RequestBody     json.RawMessage
}

func (store *AuditStore) LatestBlocked(ctx context.Context) (BlockedAuditRecord, error) {
	var record BlockedAuditRecord
	var body string
	err := store.db.QueryRowContext(ctx, `SELECT request_id, occurred_at, request_body_json
		FROM audit_events WHERE action = 'block' ORDER BY id DESC LIMIT 1`).Scan(&record.RequestID, &record.OccurredAt, &body)
	if err != nil {
		return BlockedAuditRecord{}, err
	}
	record.RequestBody = json.RawMessage(body)
	rows, err := store.db.QueryContext(ctx, `SELECT COALESCE(matched_keyword, '') FROM audit_matches m
		JOIN audit_events e ON e.id = m.event_id WHERE e.request_id = ? AND e.action = 'block'
		ORDER BY m.ordinal`, record.RequestID)
	if err != nil {
		return BlockedAuditRecord{}, err
	}
	defer rows.Close()
	seen := make(map[string]struct{})
	for rows.Next() {
		var keyword string
		if err := rows.Scan(&keyword); err != nil {
			return BlockedAuditRecord{}, err
		}
		if keyword != "" {
			if _, exists := seen[keyword]; exists {
				continue
			}
			seen[keyword] = struct{}{}
			record.MatchedKeywords = append(record.MatchedKeywords, keyword)
		}
	}
	return record, rows.Err()
}
