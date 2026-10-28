package storage

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditRequestBodySupportsMissingHistoricalBodyAndRejectsCorruption(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(t.TempDir(), "data")
	policyPath, auditPath := filepath.Join(directory, "policy.db"), filepath.Join(directory, "audit.db")
	if err := InitDatabases(ctx, policyPath, auditPath); err != nil {
		t.Fatal(err)
	}
	db, err := openDatabase(ctx, auditPath, auditDatabase, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, body := range []any{nil, "", `{"input":"audit_probe_92"}`, "invalid-json"} {
		result, err := db.ExecContext(ctx, `INSERT INTO audit_events(request_id, event_type, occurred_at, user_name, rule_set_version, action, result, match_count, duration_ms, request_body_json)
			VALUES('probe', 'decision', '2026-01-01T00:00:00Z', 'tester', '1', 'block', 'blocked', 1, 0, ?)`, body)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := result.LastInsertId()
		got, err := QueryAuditRequestBody(ctx, auditPath, id)
		if body == "invalid-json" {
			if err == nil || got.Body != "" {
				t.Fatal("损坏的正文不应作为正常内容返回")
			}
			continue
		}
		if err != nil || (body == nil && got.Body != "") || (body != nil && got.Body != body) {
			t.Fatalf("历史正文兼容错误: %+v %v", got, err)
		}
		detail, err := QueryAuditDetail(ctx, auditPath, id)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(detail)
		if strings.Contains(string(raw), "audit_probe_92") || strings.Contains(string(raw), "request_body") {
			t.Fatal("普通详情不应自动携带请求正文")
		}
	}
}
