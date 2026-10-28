//go:build windows

package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/gateway"
	"github.com/xiaotaowang/prompt-auditing/internal/settings"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestDesktopManagementAppliesRulesToBothProtocols(t *testing.T) {
	for _, mode := range []string{settings.AuthGateway, settings.AuthClient} {
		t.Run(mode, func(t *testing.T) { testDesktopManagementAuthMode(t, mode) })
	}
}

func testDesktopManagementAuthMode(t *testing.T, mode string) {
	directory := filepath.Join(t.TempDir(), "private-data")
	store, err := settings.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	values, token, key, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := &desktopController{store: store, values: values, token: token, key: key}
	defer c.stop()
	cfg, err := store.Config(values)
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeDesktopDatabases(cfg); err != nil {
		t.Fatal(err)
	}
	forwarded := make(chan string, 4)
	const sse = "data: {\"ok\":true}\n\ndata: [DONE]\n\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer desktop-test-key" || strings.Contains(string(body), "内部系统") || !strings.Contains(string(body), "业务系统") {
			t.Errorf("上游认证或脱敏内容错误")
		}
		forwarded <- r.URL.Path
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, sse)
	}))
	defer upstream.Close()
	management := httptest.NewUnstartedServer(nil)
	origin := "http://" + management.Listener.Addr().String()
	management.Config.Handler = c.managementHandler(origin, "test-session")
	management.Start()
	defer management.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	manage := func(path, method string, value any) []byte {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequest(method, origin+"/api/"+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer test-session")
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		result, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("管理操作失败: %s %s status=%d body=%s err=%v", method, path, response.StatusCode, result, err)
		}
		var failure struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(result, &failure); err != nil || failure.Error != "" {
			t.Fatalf("管理操作失败: %s %s", result, err)
		}
		return result
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	values.Listen = listener.Addr().String()
	listener.Close()
	values.Upstream = upstream.URL + "/v1"
	values.AuthMode = mode
	values.SetupRequired = false
	manage("settings", http.MethodPut, struct {
		settings.Values
		UpstreamKey string `json:"upstream_key"`
	}{values, "desktop-test-key"})
	rules := []storage.Rule{
		{Name: "客户信息拦截", Type: "keyword", Action: "block", Enabled: true, Keywords: []string{"客户A", "内部系统"}},
		{Name: "敏感字替换", Type: "keyword_mapping", Action: "mask", Enabled: true, Mappings: []storage.Mapping{{Source: "内部系统", Target: "业务系统"}}},
	}
	manage("rules", http.MethodPut, map[string]any{"rules": rules})
	var saved storage.RuleSet
	if err := json.Unmarshal(manage("rules", http.MethodGet, nil), &saved); err != nil || len(saved.Rules) != 2 {
		t.Fatalf("读取已保存规则失败: %+v %v", saved, err)
	}
	ids := map[string]string{}
	for _, rule := range saved.Rules {
		if !regexp.MustCompile(`^rule\.[0-9a-f]{32}$`).MatchString(rule.ID) {
			t.Fatalf("未自动生成规则标识: %+v", rule)
		}
		ids[rule.Name] = rule.ID
	}
	if ids["客户信息拦截"] == ids["敏感字替换"] {
		t.Fatal("新规则标识重复")
	}
	rules = saved.Rules
	manage("live-logs", http.MethodPut, map[string]bool{"enabled": true})
	for _, path := range []string{"/v1/responses", "/v1/chat/completions"} {
		for _, blocked := range []bool{true, false} {
			text, wantStatus := "内部系统", http.StatusOK
			if blocked {
				text, wantStatus = "客户A desktop-test-key", http.StatusForbidden
			}
			payload := map[string]any{"model": "test-model", "stream": true}
			if path == "/v1/responses" {
				payload["input"] = text
			} else {
				payload["messages"] = []map[string]string{{"role": "user", "content": text}}
			}
			body, _ := json.Marshal(payload)
			r, _ := http.NewRequest(http.MethodPost, "http://"+values.Listen+path, bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			credential := token
			if mode == settings.AuthClient {
				credential = "desktop-test-key"
			}
			r.Header.Set("Authorization", "Bearer "+credential)
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			result, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != wantStatus || (!blocked && string(result) != sse) {
				t.Fatalf("代理响应错误: path=%s status=%d body=%s err=%v", path, response.StatusCode, result, err)
			}
			if !blocked {
				select {
				case got := <-forwarded:
					if got != path {
						t.Fatalf("上游路径=%s", got)
					}
				case <-time.After(time.Second):
					t.Fatal("未收到上游请求")
				}
			} else if len(forwarded) != 0 {
				t.Fatal("阻断请求到达上游")
			}
		}
	}
	var live gateway.RequestLogSnapshot
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := json.Unmarshal(manage("live-logs", http.MethodGet, nil), &live); err != nil || len(live.Items) != 4 {
			t.Fatalf("实时日志未覆盖双协议请求: %+v %v", live, err)
		}
		finished := true
		for _, item := range live.Items {
			finished = finished && item.Finished
		}
		if finished || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	for _, item := range live.Items {
		wantName := "敏感字替换"
		if item.Action == "block" {
			wantName = "客户信息拦截"
		}
		if len(item.RuleNames) != 1 || item.RuleNames[0] != wantName {
			t.Fatalf("实时日志未显示规则名称: %+v", item)
		}
		if !item.Finished || (item.Action == "block" && (item.Status != 403 || item.Phase != "blocked")) || (item.Action == "mask" && (item.Status != 200 || item.UpstreamStatus != 200 || item.Phase != "completed")) {
			t.Fatalf("实际代理结果与实时日志不一致: %+v", item)
		}
	}
	var page storage.AuditPage
	if err := json.Unmarshal(manage("audits?action=block", http.MethodGet, nil), &page); err != nil || len(page.Items) != 2 {
		t.Fatalf("未查到两种协议的阻断记录: %+v %v", page, err)
	}
	var detail storage.AuditRecord
	if err := json.Unmarshal(manage("audits/"+strconv.FormatInt(page.Items[0].ID, 10), http.MethodGet, nil), &detail); err != nil || len(detail.Matches) != 1 || detail.Matches[0].RuleID != ids["客户信息拦截"] || detail.Matches[0].RuleName != "客户信息拦截" || detail.Matches[0].Keyword != "客户A" {
		t.Fatalf("管理页未返回命中规则: %+v %v", detail, err)
	}
	for _, record := range page.Items {
		var body storage.AuditRequestBody
		if err := json.Unmarshal(manage("audits/"+strconv.FormatInt(record.ID, 10)+"/request", http.MethodGet, nil), &body); err != nil || !json.Valid([]byte(body.Body)) || !strings.Contains(body.Body, "客户A") || strings.Contains(body.Body, "desktop-test-key") || !strings.Contains(body.Body, "[REDACTED_GATEWAY_CREDENTIAL]") {
			t.Fatalf("双协议正文查询或凭证脱敏错误: %+v %v", body, err)
		}
	}
	for _, test := range []struct {
		path, authorization string
		status              int
	}{
		{"audits", "", http.StatusUnauthorized},
		{"audits/" + strconv.FormatInt(detail.ID, 10), "Bearer wrong", http.StatusUnauthorized},
		{"audits/" + strconv.FormatInt(detail.ID, 10) + "/request", "", http.StatusUnauthorized},
		{"audits/" + strconv.FormatInt(detail.ID, 10) + "/request", "Bearer wrong", http.StatusUnauthorized},
		{"audits/999999", "Bearer test-session", http.StatusNotFound},
		{"audits/999999/request", "Bearer test-session", http.StatusNotFound},
		{"audits?limit=101", "Bearer test-session", http.StatusBadRequest},
		{"audits?before=invalid", "Bearer test-session", http.StatusBadRequest},
		{"audits/invalid", "Bearer test-session", http.StatusBadRequest},
		{"audits/invalid/request", "Bearer test-session", http.StatusBadRequest},
		{"audits/1/request/extra", "Bearer test-session", http.StatusBadRequest},
	} {
		request, _ := http.NewRequest(http.MethodGet, origin+"/api/"+test.path, nil)
		request.Header.Set("Authorization", test.authorization)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != test.status || strings.Contains(string(body), "客户A") {
			t.Fatalf("查询拒绝状态或信息泄露: path=%s status=%d", test.path, response.StatusCode)
		}
	}
	manage("stop", http.MethodPost, nil)
	if err := json.Unmarshal(manage("live-logs", http.MethodGet, nil), &live); err != nil || len(live.Items) != 4 || !live.Enabled {
		t.Fatal("停止代理后应保留实时日志及采集开关")
	}
	if err := json.Unmarshal(manage("audits?action=block", http.MethodGet, nil), &page); err != nil || len(page.Items) != 2 {
		t.Fatal("停止代理后应能查询审计日志")
	}
	if c.active != nil {
		t.Fatal("停止后仍持有代理实例")
	}
	manage("rules", http.MethodPut, map[string]any{"rules": rules})
	if c.active != nil {
		t.Fatal("保存规则意外启动已停止的代理")
	}
	// 改名保留内部标识，历史查询继续显示请求发生时的名称。
	for i := range rules {
		rules[i].Name = "修改后的名称"
	}
	manage("rules", http.MethodPut, map[string]any{"rules": rules})
	if err := json.Unmarshal(manage("rules", http.MethodGet, nil), &saved); err != nil || len(saved.Rules) != 2 {
		t.Fatalf("改名后读取规则失败: %+v %v", saved, err)
	}
	for _, rule := range saved.Rules {
		if rule.Name != "修改后的名称" || (rule.ID != ids["客户信息拦截"] && rule.ID != ids["敏感字替换"]) {
			t.Fatalf("改名改变了标识或未持久化: %+v", rule)
		}
	}
	if err := json.Unmarshal(manage("audits?rule_name="+url.QueryEscape("客户信息"), http.MethodGet, nil), &page); err != nil || len(page.Items) != 2 {
		t.Fatalf("无法按历史名称筛选: %+v %v", page, err)
	}
	if err := json.Unmarshal(manage("audits/"+strconv.FormatInt(detail.ID, 10), http.MethodGet, nil), &detail); err != nil || detail.Matches[0].RuleName != "客户信息拦截" {
		t.Fatalf("改名改变了审计历史: %+v %v", detail, err)
	}
	loaded, loadedToken, loadedKey, err := store.Load(context.Background())
	expectedKey := "desktop-test-key"
	if mode == settings.AuthClient {
		expectedKey = ""
	}
	if err != nil || loaded != values || loadedToken != token || loadedKey != expectedKey {
		t.Fatalf("设置未持久化: %v", err)
	}
	db, err := sql.Open("sqlite", cfg.AuditDB)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var blockedAudits int
	if err := db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE event_type='decision' AND action='block'").Scan(&blockedAudits); err != nil || blockedAudits != 2 {
		t.Fatalf("两种协议的阻断审计未写入: count=%d err=%v", blockedAudits, err)
	}
}
