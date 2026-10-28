package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/audit"
)

func TestAuditQueryCombinesResultsAndPreservesHistoricalHits(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(t.TempDir(), "data")
	policy, path := filepath.Join(directory, "policy.db"), filepath.Join(directory, "audit.db")
	if err := InitDatabases(ctx, policy, path); err != nil {
		t.Fatal(err)
	}
	store, err := OpenAudit(ctx, path, 30, 100<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	write := func(event audit.Event) {
		t.Helper()
		event.User = "tester"
		event.RuleSetVersion = "historical-version"
		event.OccurredAt = "2020-01-01T08:00:00+08:00"
		if err := store.Write(event); err != nil {
			t.Fatal(err)
		}
	}
	write(audit.Event{RequestID: "blocked", EventType: "decision", Action: "block", Result: "blocked", MatchCount: 3,
		RequestBody: json.RawMessage(`{"input":"must-not-be-returned"}`), Matches: []audit.Match{
			{RuleID: "customer", Category: "keyword", MatchedKeyword: "客户A"},
			{RuleID: "pattern", Category: "regex"},
		}})
	write(audit.Event{RequestID: "allowed", EventType: "decision", Action: "allow", Result: "forwarding"})
	status := 200
	write(audit.Event{RequestID: "allowed", EventType: "completion", Action: "allow", Result: "completed", UpstreamStatus: &status, DurationMS: 18})
	write(audit.Event{RequestID: "invalid", EventType: "system_error", Action: "block", Result: "rejected", ErrorCode: "unsupported_payload"})

	page, err := QueryAudit(ctx, path, AuditFilter{})
	if err != nil || len(page.Items) != 3 || page.Items[0].RequestID != "invalid" || page.NextBefore != 0 {
		t.Fatalf("查询应合并同一请求且不清理历史: %+v %v", page, err)
	}
	if page.Items[1].Result != "completed" || page.Items[1].UpstreamStatus == nil || *page.Items[1].UpstreamStatus != 200 || page.Items[1].DurationMS != 18 {
		t.Fatalf("未合并完成结果: %+v", page.Items[1])
	}
	blocked := page.Items[2]
	detail, err := QueryAuditDetail(ctx, path, blocked.ID)
	if err != nil || detail.RuleSetVersion != "historical-version" || len(detail.Matches) != 2 || detail.Matches[0].RuleID != "customer" || detail.Matches[0].Keyword != "客户A" || detail.Matches[1].Type != "regex" || detail.Matches[1].Keyword != "" {
		t.Fatalf("历史命中信息错误: %+v %v", detail, err)
	}
	raw, _ := json.Marshal(detail)
	if strings.Contains(string(raw), "must-not-be-returned") || strings.Contains(string(raw), "request_body") {
		t.Fatal("普通详情不应自动返回请求全文")
	}
	invalid, err := QueryAuditDetail(ctx, path, page.Items[0].ID)
	if err != nil || invalid.ErrorCode != "unsupported_payload" || len(invalid.Matches) != 0 {
		t.Fatalf("系统拒绝不应伪造规则命中: %+v %v", invalid, err)
	}
	requestBody, err := QueryAuditRequestBody(ctx, path, blocked.ID)
	if err != nil || requestBody.Body != `{"input":"must-not-be-returned"}` {
		t.Fatalf("显式查询未返回已保存的阻断请求: %+v %v", requestBody, err)
	}
	for _, record := range page.Items[:2] {
		body, err := QueryAuditRequestBody(ctx, path, record.ID)
		if err != nil || body.Body != "" {
			t.Fatalf("放行或系统拒绝不应返回正文: %+v %v", body, err)
		}
	}
	if _, err := QueryAuditRequestBody(ctx, path, 99999); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("正文查询应区分记录不存在")
	}
	if _, err := QueryAuditRequestBody(ctx, path, 0); err == nil {
		t.Fatal("正文查询未拒绝无效 ID")
	}
	filtered, err := QueryAudit(ctx, path, AuditFilter{Action: "block", RuleID: "customer", RequestID: "blocked", Since: "2020-01-01T07:59:59+08:00", Until: "2020-01-01T08:00:01+08:00"})
	if err != nil || len(filtered.Items) != 1 || filtered.Items[0].ID != blocked.ID {
		t.Fatalf("筛选或时区处理错误: %+v %v", filtered, err)
	}
	injected, err := QueryAudit(ctx, path, AuditFilter{RuleID: "customer' OR 1=1 --"})
	if err != nil || len(injected.Items) != 0 {
		t.Fatal("筛选值未按字面量处理")
	}
	first, err := QueryAudit(ctx, path, AuditFilter{Limit: 1})
	if err != nil || len(first.Items) != 1 || first.NextBefore == 0 {
		t.Fatalf("首屏分页错误: %+v %v", first, err)
	}
	write(audit.Event{RequestID: "new", EventType: "decision", Action: "allow", Result: "forwarding"})
	second, err := QueryAudit(ctx, path, AuditFilter{Limit: 1, BeforeID: first.NextBefore})
	if err != nil || len(second.Items) != 1 || second.Items[0].RequestID != "allowed" {
		t.Fatalf("新请求导致分页重复或遗漏: %+v %v", second, err)
	}
	if _, err := QueryAuditDetail(ctx, path, 99999); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("不存在记录应返回明确的未找到错误")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	stopped, err := QueryAudit(ctx, path, AuditFilter{Action: "block"})
	if err != nil || len(stopped.Items) != 2 {
		t.Fatalf("停止代理后应能查询历史: %+v %v", stopped, err)
	}
	requestBody, err = QueryAuditRequestBody(ctx, path, blocked.ID)
	if err != nil || requestBody.Body == "" {
		t.Fatalf("停止代理后应能读取阻断正文: %+v %v", requestBody, err)
	}
}

func TestAuditQueryRejectsInvalidFilters(t *testing.T) {
	for _, filter := range []AuditFilter{
		{Limit: -1}, {Limit: 101}, {BeforeID: -1}, {Action: "invalid"},
		{Since: "2026-01-01"}, {Until: "invalid"},
		{Since: "2026-01-02T00:00:00Z", Until: "2026-01-01T00:00:00Z"},
	} {
		if _, err := QueryAudit(context.Background(), "unused.db", filter); err == nil {
			t.Fatalf("非法条件未拒绝: %+v", filter)
		}
	}
}
