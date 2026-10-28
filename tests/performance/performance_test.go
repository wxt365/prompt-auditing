//go:build performance

package performance_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/audit"
	"github.com/xiaotaowang/prompt-auditing/internal/config"
	"github.com/xiaotaowang/prompt-auditing/internal/gateway"
	"github.com/xiaotaowang/prompt-auditing/internal/security"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

const performanceToken = "performance-local-token-at-least-32-bytes"

func TestOneMiBInspectionP95(t *testing.T) {
	engine := performanceEngine(t, []storage.Rule{
		{ID: "credential.openai-api-key", Type: "regex", Enabled: true, CaseSensitive: true, Action: security.ActionBlock, Pattern: `\bsk-[A-Za-z0-9_-]{20,}\b`},
		{ID: "credential.password-assignment", Type: "regex", Enabled: true, Action: security.ActionBlock, Pattern: `(?:password|passwd|pwd)\s*[:=]\s*[^\s,;]{4,}`},
		{ID: "network.private-ipv4", Type: "private_ipv4", Enabled: true, Action: security.ActionWarn},
	})
	payload := security.Payload{Texts: []security.Text{{Path: "/input", Value: strings.Repeat("normal-code ", (1<<20)/12)}}}
	if _, err := engine.Inspect(context.Background(), payload); err != nil {
		t.Fatal(err)
	}
	runtime.GC()

	durations := make([]time.Duration, 50)
	for index := range durations {
		started := time.Now()
		decision, err := engine.Inspect(context.Background(), payload)
		if err != nil {
			t.Fatal(err)
		}
		durations[index] = time.Since(started)
		if decision.Action != security.ActionAllow || len(decision.Matches) != 0 {
			t.Fatalf("性能样本产生意外处置: %#v", decision)
		}
	}
	p95 := percentile95(durations)
	t.Logf("1 MiB 纯检测 P95=%s，样本数=%d", p95, len(durations))
	if p95 > 100*time.Millisecond {
		t.Fatalf("1 MiB 纯检测 P95=%s，超过建议基线 100ms", p95)
	}
}

func TestSSEFirstByteProxyOverheadP95(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(writer, "data: {}\n\n")
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
	}))
	defer upstream.Close()
	parsedUpstream, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := gateway.NewHandler(gateway.Options{
		Upstream: parsedUpstream, Client: upstream.Client(), Engine: performanceEngine(t, nil), Audit: &performanceAuditor{},
		LocalToken: performanceToken, UpstreamKey: "performance-upstream-key", OSUser: "performance-user",
		Limits: config.LimitsConfig{MaxCompressedBytes: 5 << 20, MaxDecompressedBytes: 5 << 20, MaxConcurrent: 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	gatewayServer := httptest.NewServer(handler)
	defer gatewayServer.Close()

	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	body := []byte(`{"model":"gpt-test","input":"normal","stream":true}`)
	measureFirstByte(t, client, upstream.URL, body, false)
	measureFirstByte(t, client, gatewayServer.URL+"/v1/responses", body, true)
	overheads := make([]time.Duration, 50)
	for index := range overheads {
		direct := measureFirstByte(t, client, upstream.URL, body, false)
		proxied := measureFirstByte(t, client, gatewayServer.URL+"/v1/responses", body, true)
		if proxied > direct {
			overheads[index] = proxied - direct
		}
	}
	p95 := percentile95(overheads)
	t.Logf("SSE 首字节额外代理延迟 P95=%s，样本数=%d", p95, len(overheads))
	if p95 > 150*time.Millisecond {
		t.Fatalf("SSE 首字节额外代理延迟 P95=%s，超过建议基线 150ms", p95)
	}
}

type performanceAuditor struct {
	mu        sync.Mutex
	unhealthy bool
}

func (*performanceAuditor) Write(audit.Event) error { return nil }
func (auditor *performanceAuditor) Healthy() bool {
	auditor.mu.Lock()
	defer auditor.mu.Unlock()
	return !auditor.unhealthy
}
func (auditor *performanceAuditor) MarkUnhealthy() {
	auditor.mu.Lock()
	auditor.unhealthy = true
	auditor.mu.Unlock()
}

func performanceEngine(t *testing.T, rules []storage.Rule) *security.Engine {
	t.Helper()
	engine, err := security.NewEngine(storage.RuleSet{Version: "1", DefaultAction: storage.DefaultAction, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func measureFirstByte(t *testing.T, client *http.Client, endpoint string, body []byte, authorized bool) time.Duration {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if authorized {
		request.Header.Set("Authorization", "Bearer "+performanceToken)
	}
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("性能请求状态 = %d %s", response.StatusCode, data)
	}
	var first [1]byte
	if _, err := io.ReadFull(response.Body, first[:]); err != nil {
		t.Fatal(err)
	}
	return time.Since(started)
}

func percentile95(values []time.Duration) time.Duration {
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	index := (95*len(sorted)+99)/100 - 1
	return sorted[index]
}
