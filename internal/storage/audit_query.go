package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/xiaotaowang/prompt-auditing/internal/platform"
)

type AuditFilter struct {
	Action, RequestID, RuleID string
	RuleName                  string
	Since, Until              string
	BeforeID                  int64
	Limit                     int
}

type AuditHit struct {
	Action   string `json:"action"`
	Reason   string `json:"reason"`
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Type     string `json:"type"`
	Keyword  string `json:"keyword"`
}

// 一次请求只展示一行，转发结果取最后一条完成事件，命中信息取原始决策事件。
type AuditRecord struct {
	ID             int64      `json:"id"`
	RequestID      string     `json:"request_id"`
	OccurredAt     string     `json:"occurred_at"`
	EventType      string     `json:"event_type"`
	User           string     `json:"user"`
	RuleSetVersion string     `json:"rule_set_version"`
	Action         string     `json:"action"`
	Result         string     `json:"result"`
	MatchCount     int        `json:"match_count"`
	UpstreamStatus *int       `json:"upstream_status"`
	DurationMS     int64      `json:"duration_ms"`
	ErrorCode      string     `json:"error_code"`
	Matches        []AuditHit `json:"matches,omitempty"`
}

type AuditPage struct {
	Items      []AuditRecord `json:"items"`
	NextBefore int64         `json:"next_before"`
}

type AuditRequestBody struct {
	Body string `json:"request_body"`
}

// 正文独立按需读取，列表和普通详情不携带完整请求。
func QueryAuditRequestBody(ctx context.Context, path string, id int64) (AuditRequestBody, error) {
	if id <= 0 {
		return AuditRequestBody{}, errors.New("审计记录 ID 无效")
	}
	db, err := openAuditReader(ctx, path)
	if err != nil {
		return AuditRequestBody{}, err
	}
	defer db.Close()
	var result AuditRequestBody
	err = db.QueryRowContext(ctx, `SELECT CASE WHEN event_type = 'decision' AND action = 'block'
		THEN COALESCE(request_body_json, '') ELSE '' END FROM audit_events
		WHERE id = ? AND event_type IN ('decision', 'system_error')`, id).Scan(&result.Body)
	if err != nil {
		return AuditRequestBody{}, err
	}
	if result.Body != "" && !json.Valid([]byte(result.Body)) {
		return AuditRequestBody{}, errors.New("已保存的请求内容不是有效 JSON")
	}
	return result, nil
}

// 只读连接既可查询运行中的 WAL，也可在代理停止时查询，不触发清理和数据库重建。
func openAuditReader(ctx context.Context, path string) (*sql.DB, error) {
	if err := platform.ValidateSecureDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := platform.ValidateSecureFile(path); err != nil {
		return nil, err
	}
	if err := validateExistingSidecars(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", sqliteDSN(path)+"?mode=ro")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.ExecContext(ctx, "PRAGMA busy_timeout = 3000"); err == nil {
		err = verifyMigrationState(ctx, db)
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

const auditRequestSelect = `SELECT e.id, e.request_id, e.occurred_at, e.event_type, e.user_name,
	e.rule_set_version, e.action, COALESCE(c.result, e.result), e.match_count,
	c.upstream_status, COALESCE(c.duration_ms, e.duration_ms), COALESCE(c.error_code, e.error_code, '')
	FROM audit_events e LEFT JOIN audit_events c ON c.id = (
		SELECT id FROM audit_events WHERE request_id = e.request_id AND event_type = 'completion' ORDER BY id DESC LIMIT 1
	) `

func scanAuditRecord(row interface{ Scan(...any) error }) (AuditRecord, error) {
	var record AuditRecord
	err := row.Scan(&record.ID, &record.RequestID, &record.OccurredAt, &record.EventType, &record.User,
		&record.RuleSetVersion, &record.Action, &record.Result, &record.MatchCount,
		&record.UpstreamStatus, &record.DurationMS, &record.ErrorCode)
	return record, err
}

func QueryAudit(ctx context.Context, path string, filter AuditFilter) (AuditPage, error) {
	page := AuditPage{Items: []AuditRecord{}}
	if filter.Limit == 0 {
		filter.Limit = 50
	}
	if filter.Limit < 1 || filter.Limit > 100 || filter.BeforeID < 0 {
		return page, errors.New("分页参数无效，每页须为 1 至 100 条")
	}
	if len(filter.RequestID) > 128 || len(filter.RuleID) > 128 {
		return page, errors.New("请求 ID 或规则 ID 过长")
	}
	if utf8.RuneCountInString(filter.RuleName) > 128 {
		return page, errors.New("规则名称过长")
	}
	where := []string{"e.event_type IN ('decision', 'system_error')"}
	args := []any{}
	if filter.Action != "" {
		switch filter.Action {
		case "block", "mask", "warn", "allow":
		default:
			return page, errors.New("审计动作无效")
		}
		where = append(where, "e.action = ?")
		args = append(args, filter.Action)
	}
	if filter.RequestID != "" {
		where = append(where, "e.request_id = ?")
		args = append(args, filter.RequestID)
	}
	if filter.RuleID != "" {
		where = append(where, "EXISTS (SELECT 1 FROM audit_matches m WHERE m.event_id = e.id AND m.rule_id = ?)")
		args = append(args, filter.RuleID)
	}
	if filter.RuleName != "" {
		where = append(where, "EXISTS (SELECT 1 FROM audit_matches m WHERE m.event_id = e.id AND instr(CASE WHEN m.rule_name = '' THEN m.rule_id ELSE m.rule_name END, ?) > 0)")
		args = append(args, filter.RuleName)
	}
	var since, until time.Time
	for _, bound := range []struct {
		value, clause string
		target        *time.Time
	}{
		{filter.Since, "julianday(e.occurred_at) >= julianday(?)", &since},
		{filter.Until, "julianday(e.occurred_at) <= julianday(?)", &until},
	} {
		if bound.value == "" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339Nano, bound.value)
		if err != nil {
			return page, errors.New("查询时间必须包含时区")
		}
		*bound.target = parsed
		where = append(where, bound.clause)
		args = append(args, parsed.UTC().Format(time.RFC3339Nano))
	}
	if !since.IsZero() && !until.IsZero() && since.After(until) {
		return page, errors.New("开始时间不能晚于结束时间")
	}
	if filter.BeforeID != 0 {
		where = append(where, "e.id < ?")
		args = append(args, filter.BeforeID)
	}
	args = append(args, filter.Limit+1)
	db, err := openAuditReader(ctx, path)
	if err != nil {
		return page, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, auditRequestSelect+"WHERE "+strings.Join(where, " AND ")+" ORDER BY e.id DESC LIMIT ?", args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		record, err := scanAuditRecord(rows)
		if err != nil {
			return page, err
		}
		if len(page.Items) == filter.Limit {
			page.NextBefore = page.Items[len(page.Items)-1].ID
			break
		}
		page.Items = append(page.Items, record)
	}
	return page, rows.Err()
}

func QueryAuditDetail(ctx context.Context, path string, id int64) (AuditRecord, error) {
	if id <= 0 {
		return AuditRecord{}, errors.New("审计记录 ID 无效")
	}
	db, err := openAuditReader(ctx, path)
	if err != nil {
		return AuditRecord{}, err
	}
	defer db.Close()
	record, err := scanAuditRecord(db.QueryRowContext(ctx, auditRequestSelect+"WHERE e.id = ? AND e.event_type IN ('decision', 'system_error')", id))
	if err != nil {
		return AuditRecord{}, err
	}
	rows, err := db.QueryContext(ctx, "SELECT rule_id, rule_name, category, COALESCE(matched_keyword, ''), action, reason FROM audit_matches WHERE event_id = ? ORDER BY ordinal", id)
	if err != nil {
		return AuditRecord{}, err
	}
	defer rows.Close()
	record.Matches = []AuditHit{}
	for rows.Next() {
		var hit AuditHit
		if err := rows.Scan(&hit.RuleID, &hit.RuleName, &hit.Type, &hit.Keyword, &hit.Action, &hit.Reason); err != nil {
			return AuditRecord{}, fmt.Errorf("读取命中规则: %w", err)
		}
		record.Matches = append(record.Matches, hit)
	}
	return record, rows.Err()
}
