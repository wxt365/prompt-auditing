package integration_test

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/config"
	"github.com/xiaotaowang/prompt-auditing/internal/gateway"
	"github.com/xiaotaowang/prompt-auditing/internal/security"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestUpstreamHTTPResultPersistsAfterReplacement(t *testing.T) {
	const localToken = "probe_local_token_92_at_least_32_bytes"
	for _, path := range []string{"/v1/responses", "/v1/chat/completions"} {
		for _, encoding := range []string{"plain", "gzip"} {
			for _, status := range []int{200, 401, 422, 429, 500} {
				t.Run(fmt.Sprintf("%s/%s/%d", path, encoding, status), func(t *testing.T) {
					ctx := context.Background()
					directory := filepath.Join(t.TempDir(), "data")
					policyPath, auditPath := filepath.Join(directory, "policy.db"), filepath.Join(directory, "audit.db")
					if err := storage.InitDatabases(ctx, policyPath, auditPath); err != nil {
						t.Fatal(err)
					}
					store, err := storage.OpenAudit(ctx, auditPath, 30, 100<<20)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = store.Close() })
					engine, err := security.NewEngine(storage.RuleSet{Version: "1", DefaultAction: "allow", Rules: []storage.Rule{
						{ID: "probe.mapping", Name: "测试替换", Type: "keyword_mapping", Action: "mask", Enabled: true,
							Mappings: []storage.Mapping{{Source: "probe_source_92", Target: "probe_safe_92"}}},
					}})
					if err != nil {
						t.Fatal(err)
					}
					var calls atomic.Int32
					const responseBody = `{"message":"probe_upstream_92"}`
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						body, err := io.ReadAll(r.Body)
						if err != nil || r.URL.Path != path || strings.Contains(string(body), "probe_source_92") || !strings.Contains(string(body), "probe_safe_92") {
							t.Error("上游未收到正确路径或替换后的正文", err)
						}
						w.Header().Set("Content-Type", "application/json")
						if encoding == "gzip" {
							w.Header().Set("Content-Encoding", "gzip")
						}
						w.WriteHeader(status)
						if encoding == "gzip" {
							compressed := gzip.NewWriter(w)
							_, _ = io.WriteString(compressed, responseBody)
							_ = compressed.Close()
						} else {
							_, _ = io.WriteString(w, responseBody)
						}
					}))
					defer upstream.Close()
					client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
					defer client.CloseIdleConnections()
					target, _ := url.Parse(upstream.URL)
					logs := &gateway.RequestLog{}
					logs.SetEnabled(true)
					handler, err := gateway.NewHandler(gateway.Options{
						Upstream: target, Client: client, Engine: engine, Audit: store, RequestLog: logs,
						LocalToken: localToken, UpstreamKey: "probe_upstream_key_92", OSUser: "probe-user",
						Limits: config.LimitsConfig{MaxCompressedBytes: 1 << 20, MaxDecompressedBytes: 1 << 20, MaxConcurrent: 10},
					})
					if err != nil {
						t.Fatal(err)
					}
					payload := `{"input":"probe_source_92"}`
					if path == "/v1/chat/completions" {
						payload = `{"messages":[{"role":"user","content":"probe_source_92"}]}`
					}
					req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(payload))
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Authorization", "Bearer "+localToken)
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, req)
					if response.Code != status || calls.Load() != 1 {
						t.Fatalf("原始状态码或上游调用次数错误: status=%d calls=%d", response.Code, calls.Load())
					}
					var decoded map[string]string
					var reader io.Reader = response.Body
					if status == http.StatusOK && encoding == "gzip" {
						compressed, err := gzip.NewReader(response.Body)
						if err != nil {
							t.Fatal(err)
						}
						defer compressed.Close()
						reader = compressed
					}
					if err := json.NewDecoder(reader).Decode(&decoded); err != nil || decoded["message"] != "probe_upstream_92" {
						t.Fatal("响应正文转发不正确", err)
					}
					wantResult, wantCode, wantPhase := "upstream_http_error", "upstream_http_error", "failed"
					if status == http.StatusOK {
						wantResult, wantCode, wantPhase = "completed", "", "completed"
					} else if response.Header().Get("Content-Encoding") != "" {
						t.Fatal("错误响应已解压，不能继续保留压缩标记")
					}
					live := logs.Snapshot().Items[0]
					if !live.Finished || live.Phase != wantPhase || live.ErrorCode != wantCode || live.UpstreamStatus != status || live.AuditError {
						t.Fatalf("实时日志结果不正确: %+v", live)
					}
					// 关闭写连接后再查询，确认管理页读取的是持久化结果。
					if err := store.Close(); err != nil {
						t.Fatal(err)
					}
					page, err := storage.QueryAudit(ctx, auditPath, storage.AuditFilter{})
					if err != nil || len(page.Items) != 1 {
						t.Fatalf("审计列表查询错误: items=%d err=%v", len(page.Items), err)
					}
					for _, detail := range []bool{false, true} {
						item := page.Items[0]
						if detail {
							item, err = storage.QueryAuditDetail(ctx, auditPath, item.ID)
							if err != nil {
								t.Fatal(err)
							}
						}
						if item.RequestID != response.Header().Get("x-gateway-request-id") || item.Action != "mask" || item.MatchCount != 1 ||
							item.Result != wantResult || item.ErrorCode != wantCode || item.UpstreamStatus == nil || *item.UpstreamStatus != status {
							t.Fatalf("持久化审计丢失决策或转发结果: %+v", item)
						}
					}
				})
			}
		}
	}
}
