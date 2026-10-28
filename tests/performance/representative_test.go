//go:build performance

package performance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/config"
	"github.com/xiaotaowang/prompt-auditing/internal/gateway"
	"github.com/xiaotaowang/prompt-auditing/internal/security"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

// 使用独立样本模拟两条预置规则的规模，避免输出或依赖用户的实际匹配内容。
func representativeRuleSet() storage.RuleSet {
	mappings := make([]storage.Mapping, 16)
	for i := range mappings {
		mappings[i] = storage.Mapping{Source: fmt.Sprintf("probe_source_%02d_92", i), Target: "probe_safe_92"}
	}
	keywords := make([]string, 36)
	for i := range keywords {
		keywords[i] = fmt.Sprintf("probe_denied_%02d_92", i)
	}
	return storage.RuleSet{Version: "1", DefaultAction: "allow", Rules: []storage.Rule{
		{ID: "mapping", Type: "keyword_mapping", Action: "mask", Enabled: true, Mappings: mappings},
		{ID: "denied", Type: "keyword", Action: "block", Enabled: true, Keywords: keywords},
		{ID: "regex.one", Type: "regex", Action: "block", Enabled: true, Pattern: `credential_probe_[0-9]{20}`},
		{ID: "regex.two", Type: "regex", Action: "block", Enabled: true, Pattern: `secret_probe_[0-9]{20}`},
	}}
}

func BenchmarkRepresentativeInspection(b *testing.B) {
	benchmarkRepresentativeInspection(b, "normal_text_92 ")
}

func BenchmarkMixedTextInspection(b *testing.B) {
	benchmarkRepresentativeInspection(b, "normal_text_92 中文样本 ＡＢＣ Straße e\u0301 ")
}

func benchmarkRepresentativeInspection(b *testing.B, unit string) {
	for _, size := range []int{64 << 10, 1 << 20, 5 << 20} {
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			engine, err := security.NewEngine(representativeRuleSet())
			if err != nil {
				b.Fatal(err)
			}
			value := strings.Repeat(unit, size/len(unit))
			payload := security.Payload{Texts: []security.Text{{Path: "/input", Value: value, Maskable: true}}}
			b.ReportAllocs()
			b.SetBytes(int64(len(value)))
			b.ResetTimer()
			for range b.N {
				decision, err := engine.Inspect(context.Background(), payload)
				if err != nil || decision.Action != security.ActionAllow || len(decision.Matches) != 0 {
					b.Fatal("代表性检测样本失败", err)
				}
			}
		})
	}
}

func TestSQLiteSSELatencyWithRepresentativeRules(t *testing.T) {
	for _, endpoint := range []string{"/v1/responses", "/v1/chat/completions"} {
		for _, concurrency := range []int{1, 10} {
			t.Run(fmt.Sprintf("%s/concurrency_%d", endpoint, concurrency), func(t *testing.T) {
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
				defer store.Close()
				engine := performanceEngine(t, representativeRuleSet().Rules)
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, "data: {}\n\n")
					w.(http.Flusher).Flush()
				}))
				defer upstream.Close()
				target, _ := url.Parse(upstream.URL)
				live := &gateway.RequestLog{}
				live.SetEnabled(true)
				handler, err := gateway.NewHandler(gateway.Options{Upstream: target, Client: upstream.Client(),
					Engine: engine, Audit: store, RequestLog: live, LocalToken: performanceToken,
					UpstreamKey: "probe_upstream_key_92", OSUser: "performance-user",
					Limits: config.LimitsConfig{MaxCompressedBytes: 5 << 20, MaxDecompressedBytes: 5 << 20, MaxConcurrent: 10}})
				if err != nil {
					t.Fatal(err)
				}
				server := httptest.NewServer(handler)
				defer server.Close()
				client := &http.Client{Timeout: 15 * time.Second}
				defer client.CloseIdleConnections()
				const samples = 30
				durations := make([]time.Duration, samples)
				failures := make(chan error, samples)
				var workers sync.WaitGroup
				content := strings.Repeat("normal_text_92 ", (64<<10)/15) + "probe_source_00_92"
				payload := map[string]any{"model": "probe_model_92", "stream": true}
				if endpoint == "/v1/responses" {
					payload["input"] = content
				} else {
					payload["messages"] = []map[string]any{{"role": "user", "content": content}}
				}
				body, _ := json.Marshal(payload)
				started := time.Now()
				for worker := range concurrency {
					workers.Add(1)
					go func(worker int) {
						defer workers.Done()
						for i := worker; i < samples; i += concurrency {
							request, err := http.NewRequest(http.MethodPost, server.URL+endpoint, bytes.NewReader(body))
							if err != nil {
								failures <- err
								continue
							}
							request.Header.Set("Authorization", "Bearer "+performanceToken)
							request.Header.Set("Content-Type", "application/json")
							requestStarted := time.Now()
							response, err := client.Do(request)
							if err != nil {
								failures <- err
								continue
							}
							var first [1]byte
							_, readErr := io.ReadFull(response.Body, first[:])
							durations[i] = time.Since(requestStarted)
							_, drainErr := io.Copy(io.Discard, response.Body)
							response.Body.Close()
							if response.StatusCode != http.StatusOK || readErr != nil || drainErr != nil {
								failures <- fmt.Errorf("状态=%d，首字节=%v，完成=%v", response.StatusCode, readErr, drainErr)
							}
						}
					}(worker)
				}
				workers.Wait()
				elapsed := time.Since(started)
				close(failures)
				for failure := range failures {
					t.Error(failure)
				}
				if t.Failed() {
					return
				}
				// 完成事件在响应结束后写入，等待落库再检查，避免把响应 EOF 当成事务完成。
				deadline := time.Now().Add(5 * time.Second)
				for {
					snapshot := live.Snapshot()
					finished := len(snapshot.Items) == samples
					for _, item := range snapshot.Items {
						finished = finished && item.Finished
						if item.Finished && (item.Phase != "completed" || item.AuditError || item.Action != "mask") {
							t.Fatal("请求完成状态或审计状态异常")
						}
					}
					if finished {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("等待完成审计超时")
					}
					time.Sleep(5 * time.Millisecond)
				}
				page, err := storage.QueryAudit(ctx, auditPath, storage.AuditFilter{Limit: 100})
				if err != nil || len(page.Items) != samples || !store.Healthy() {
					t.Fatal("审计记录数量或健康状态不一致", err)
				}
				for _, item := range page.Items {
					if item.Action != "mask" || item.Result != "completed" || item.UpstreamStatus == nil || *item.UpstreamStatus != 200 {
						t.Fatal("持久化记录未正确合并转发结果")
					}
				}
				t.Logf("64 KiB，替换+SQLite FULL 审计+实时采集，样本=%d，并发=%d，首字节 P95=%s，批次吞吐=%.1f 请求/秒", samples, concurrency, percentile95(durations), float64(samples)/elapsed.Seconds())
			})
		}
	}
}
