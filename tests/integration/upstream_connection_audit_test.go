package integration_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/config"
	"github.com/xiaotaowang/prompt-auditing/internal/gateway"
	"github.com/xiaotaowang/prompt-auditing/internal/security"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestConnectionFailuresPersistWithoutLiveCapture(t *testing.T) {
	const localToken = "probe_local_token_92_at_least_32_bytes"
	const upstreamKey = "probe_upstream_key_92"
	for _, path := range []string{"/v1/responses", "/v1/chat/completions"} {
		for _, capture := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/capture_%t", path, capture), func(t *testing.T) {
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
				closed := false
				t.Cleanup(func() {
					if !closed {
						_ = store.Close()
					}
				})
				engine, err := security.NewEngine(storage.RuleSet{Version: "1", DefaultAction: "allow"})
				if err != nil {
					t.Fatal(err)
				}
				logs := &gateway.RequestLog{}
				logs.SetEnabled(capture)
				target, _ := url.Parse("https://probe.invalid/v1")
				var records []storage.AuditRecord
				for _, scenario := range []struct {
					name, code, result, phase string
					status, upstreamStatus    int
				}{
					{"dns", "upstream_dns_error", "upstream_error", "failed", 502, 0},
					{"refused", "upstream_connection_refused", "upstream_error", "failed", 502, 0},
					{"certificate", "upstream_tls_error", "upstream_error", "failed", 502, 0},
					{"handshake", "upstream_tls_error", "upstream_error", "failed", 502, 0},
					{"timeout", "upstream_timeout", "upstream_error", "failed", 504, 0},
					{"internal_cancel", "upstream_error", "upstream_error", "failed", 502, 0},
					{"client_cancel", "client_canceled", "client_canceled", "interrupted", 502, 0},
					{"stream_timeout", "upstream_timeout", "upstream_stream_error", "failed", 200, 200},
					{"stream_cancel", "client_canceled", "client_canceled", "interrupted", 200, 200},
					{"error_body_timeout", "upstream_timeout", "upstream_error", "failed", 500, 500},
					{"error_body_cancel", "client_canceled", "client_canceled", "interrupted", 500, 500},
					{"unknown", "upstream_error", "upstream_error", "failed", 502, 0},
				} {
					requestCtx, cancel := context.WithCancel(ctx)
					transport := connectionFailureTransport(func(r *http.Request) (*http.Response, error) {
						switch scenario.name {
						case "dns":
							return nil, &net.DNSError{Name: "probe.invalid", Err: "probe DNS failure"}
						case "refused":
							return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
						case "certificate":
							return nil, &tls.CertificateVerificationError{Err: errors.New("probe certificate failure")}
						case "handshake":
							err := errors.New("probe handshake rejection")
							httptrace.ContextClientTrace(r.Context()).TLSHandshakeDone(tls.ConnectionState{}, err)
							return nil, err
						case "timeout":
							return nil, context.DeadlineExceeded
						case "client_cancel":
							cancel()
							return nil, context.Canceled
						case "internal_cancel":
							return nil, context.Canceled
						}
						if scenario.upstreamStatus != 0 {
							reader := connectionFailureReader(func([]byte) (int, error) {
								if strings.HasSuffix(scenario.name, "cancel") {
									cancel()
									return 0, context.Canceled
								}
								return 0, context.DeadlineExceeded
							})
							contentType, prefix := "application/json", ""
							if scenario.upstreamStatus == 200 {
								contentType, prefix = "text/event-stream", "data: {}\n\n"
							}
							return &http.Response{StatusCode: scenario.upstreamStatus, Request: r,
								Header: http.Header{"Content-Type": {contentType}},
								Body:   io.NopCloser(io.MultiReader(strings.NewReader(prefix), reader))}, nil
						}
						return nil, errors.New("probe unknown failure " + localToken + " " + upstreamKey)
					})
					handler, err := gateway.NewHandler(gateway.Options{
						Upstream: target, Client: &http.Client{Transport: transport}, Engine: engine, Audit: store,
						LocalToken: localToken, UpstreamKey: upstreamKey, RequestLog: logs, OSUser: "probe-user",
						Limits: config.LimitsConfig{MaxCompressedBytes: 1 << 20, MaxDecompressedBytes: 1 << 20, MaxConcurrent: 10},
					})
					if err != nil {
						cancel()
						t.Fatal(err)
					}
					payload := `{"input":"probe_request_body_92"}`
					if path == "/v1/chat/completions" {
						payload = `{"messages":[{"role":"user","content":"probe_request_body_92"}]}`
					}
					req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(payload)).WithContext(requestCtx)
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Authorization", "Bearer "+localToken)
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, req)
					cancel()
					if response.Code != scenario.status {
						t.Fatalf("%s 响应状态错误: %d", scenario.name, response.Code)
					}
					requestID := response.Header().Get("x-gateway-request-id")
					page, err := storage.QueryAudit(ctx, auditPath, storage.AuditFilter{RequestID: requestID})
					if err != nil || len(page.Items) != 1 {
						t.Fatalf("%s 审计查询失败: items=%d err=%v", scenario.name, len(page.Items), err)
					}
					item := page.Items[0]
					if item.Result != scenario.result || item.ErrorCode != scenario.code || item.Action != "allow" ||
						(scenario.upstreamStatus == 0 && item.UpstreamStatus != nil) ||
						(scenario.upstreamStatus != 0 && (item.UpstreamStatus == nil || *item.UpstreamStatus != scenario.upstreamStatus)) {
						t.Fatalf("%s 持久化失败原因不正确: %+v", scenario.name, item)
					}
					records = append(records, item)
					if capture {
						live := logs.Snapshot().Items[0]
						if !live.Finished || live.Phase != scenario.phase || live.ErrorCode != scenario.code || live.AuditError {
							t.Fatalf("%s 实时日志与审计不一致: %+v", scenario.name, live)
						}
					} else if len(logs.Snapshot().Items) != 0 {
						t.Fatal("采集关闭时不应生成实时日志")
					}
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
				closed = true
				for _, record := range records {
					detail, err := storage.QueryAuditDetail(ctx, auditPath, record.ID)
					if err != nil || detail.ErrorCode != record.ErrorCode || detail.Result != record.Result {
						t.Fatal("关闭写连接后丢失持久化失败原因", err)
					}
				}
				live, _ := json.Marshal(logs.Snapshot())
				data, err := os.ReadFile(auditPath)
				if err != nil {
					t.Fatal(err)
				}
				for _, forbidden := range []string{localToken, upstreamKey, "probe_request_body_92"} {
					if strings.Contains(string(data), forbidden) || strings.Contains(string(live), forbidden) {
						t.Fatal("连接诊断泄露凭证或请求正文")
					}
				}
			})
		}
	}
}

type connectionFailureTransport func(*http.Request) (*http.Response, error)

func (f connectionFailureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type connectionFailureReader func([]byte) (int, error)

func (f connectionFailureReader) Read(p []byte) (int, error) {
	return f(p)
}
