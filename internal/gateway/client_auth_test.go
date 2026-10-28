package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/config"
	"github.com/xiaotaowang/prompt-auditing/internal/security"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func newClientAuthHandler(t *testing.T, upstream string, auditor *memoryAuditor, rules []storage.Rule) *Handler {
	t.Helper()
	engine, err := security.NewEngine(storage.RuleSet{Version: "1", DefaultAction: storage.DefaultAction, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{Upstream: target, Client: upstreamClient(), Engine: engine, Audit: auditor, ClientAuth: true,
		Limits: config.LimitsConfig{MaxCompressedBytes: 1 << 20, MaxDecompressedBytes: 1 << 20, MaxConcurrent: 32}})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestClientAuthPreservesEachRequestsCredential(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			User string `json:"user"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Error(err)
		}
		if r.Header.Get("Authorization") != "bearer "+payload.User || strings.Contains(string(body), "内部系统") || !strings.Contains(string(body), "业务系统") {
			t.Error("请求认证串用或脱敏失败")
		}
		if payload.User == "key-0" {
			w.Header().Set("Location", "https://example.invalid/")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()
	handler := newClientAuthHandler(t, upstream.URL+"/v1", &memoryAuditor{failAfter: -1}, []storage.Rule{{ID: "mask", Type: "keyword_mapping", Action: "mask", Enabled: true, Mappings: []storage.Mapping{{Source: "内部系统", Target: "业务系统"}}}})
	var group sync.WaitGroup
	for index := 0; index < 16; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			path := responsesPath
			body := fmt.Sprintf(`{"user":"key-%d","input":"内部系统"}`, index)
			if index%2 != 0 {
				path = chatCompletionsPath
				body = fmt.Sprintf(`{"user":"key-%d","messages":[{"role":"user","content":"内部系统"}]}`, index)
			}
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", fmt.Sprintf("bearer key-%d", index))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if index == 0 {
				if w.Code != http.StatusTemporaryRedirect || w.Header().Get("Location") != "" {
					t.Error("认证请求不应跟随重定向")
				}
			} else if w.Code != http.StatusOK || w.Body.String() != "data: [DONE]\n\n" {
				t.Errorf("请求失败: %d %s", w.Code, w.Body.String())
			}
		}()
	}
	group.Wait()
	if handler.localToken != "" || handler.upstreamKey != "" {
		t.Fatal("客户端凭证被保存到共享 Handler")
	}
}

func TestClientAuthRejectsMissingOrAmbiguousCredentials(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("无效认证不应到达上游") }))
	defer upstream.Close()
	handler := newClientAuthHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, nil)
	for _, headers := range [][]string{nil, {"Bearer "}, {"Basic key"}, {"Bearer key extra"}, {"Bearer first", "Bearer second"}} {
		r := httptest.NewRequest(http.MethodPost, responsesPath, strings.NewReader(`{"input":"normal"}`))
		for _, header := range headers {
			r.Header.Add("Authorization", header)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("无效认证通过: %d", w.Code)
		}
	}
}

func TestClientAuthRedactsCredentialsFromAuditsAndUpstreamErrors(t *testing.T) {
	const credential = "request-only-private-credential"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Diagnostic", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, `{"error":"%s"}`, r.Header.Get("Authorization"))
	}))
	defer upstream.Close()
	auditor := &memoryAuditor{failAfter: -1}
	handler := newClientAuthHandler(t, upstream.URL, auditor, []storage.Rule{{ID: "block", Type: "keyword", Action: "block", Enabled: true, Keywords: []string{credential}}})
	for _, body := range []string{`{"input":"` + credential + `"}`, `{"input":"normal"}`} {
		r := httptest.NewRequest(http.MethodPost, responsesPath, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+credential)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
			t.Fatal(w.Code)
		}
		if strings.Contains(w.Body.String(), credential) || strings.Contains(w.Header().Get("X-Diagnostic"), credential) {
			t.Fatal("响应泄露客户端凭证")
		}
	}
	raw, err := json.Marshal(auditor.events)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(credential)) || !bytes.Contains(raw, []byte(redactedCredential)) {
		t.Fatal("审计未清除请求凭证")
	}
}

func TestUnsupportedPayloadReportsReasonWithoutCredential(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("无效载荷不应到达上游") }))
	defer upstream.Close()
	handler := newClientAuthHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, nil)
	var detail string
	handler.payloadError = func(value string) { detail = value }
	r := httptest.NewRequest(http.MethodPost, responsesPath, strings.NewReader(`{"input":[{"type":"input_file-private-key"}]}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer private-key")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "input_file-") || strings.Contains(w.Body.String(), "private-key") || strings.Contains(detail, "private-key") {
		t.Fatalf("诊断未提供路径或泄露凭证: %s %s", w.Body.String(), detail)
	}
}
