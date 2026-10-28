package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/security"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
)

func TestRequestLogCaptureBoundaries(t *testing.T) {
	logs := &RequestLog{}
	if logs.begin("off", "POST", responsesPath) != nil || logs.Snapshot().Enabled {
		t.Fatal("实时采集必须默认关闭")
	}
	logs.SetEnabled(true)
	old := logs.begin("old", "POST", responsesPath)
	old.phase("forwarding")
	logs.SetEnabled(false)
	logs.SetEnabled(true)
	old.status(200)
	old.finish(true, false)
	snapshot := logs.Snapshot()
	if snapshot.Items[0].Phase != "capture_stopped" || snapshot.Items[0].Status != 0 {
		t.Fatal("重新开启后不应更新先前的在途请求")
	}
	logs.Clear()
	old.phase("responding")
	if !logs.Snapshot().Enabled || len(logs.Snapshot().Items) != 0 {
		t.Fatal("清空不应关闭采集或被旧请求重新写入")
	}
	for i := 0; i < requestLogCapacity+3; i++ {
		trace := logs.begin(fmt.Sprint(i), "POST", responsesPath)
		trace.update(func(e *RequestLogEntry) {
			e.RuleIDs = []string{"original"}
			e.RuleNames = []string{"原名称"}
		})
		trace.status(200)
		trace.finish(true, false)
	}
	snapshot = logs.Snapshot()
	if len(snapshot.Items) != requestLogCapacity || snapshot.Dropped != 3 || snapshot.Items[0].RequestID != "502" || snapshot.Items[499].RequestID != "3" {
		t.Fatal("最近请求的容量或淘汰顺序错误")
	}
	snapshot.Items[0].RuleIDs[0] = "changed"
	snapshot.Items[0].RuleNames[0] = "已修改"
	if logs.Snapshot().Items[0].RuleIDs[0] != "original" || logs.Snapshot().Items[0].RuleNames[0] != "原名称" {
		t.Fatal("查询快照不应允许修改采集缓冲区")
	}
}

func TestRequestLogConcurrentRequests(t *testing.T) {
	logs := &RequestLog{}
	logs.SetEnabled(true)
	var workers sync.WaitGroup
	for i := 0; i < 12; i++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for j := 0; j < 60; j++ {
				trace := logs.begin(fmt.Sprintf("%d-%d", worker, j), "POST", responsesPath)
				trace.phase("forwarding")
				trace.status(200)
				_ = logs.Snapshot()
				trace.finish(true, false)
			}
		}(i)
	}
	workers.Wait()
	seen := map[uint64]bool{}
	for _, item := range logs.Snapshot().Items {
		if seen[item.ID] || !item.Finished || item.Status != 200 {
			t.Fatal("并发请求采集重复或相互覆盖")
		}
		seen[item.ID] = true
	}
}

func TestRequestLogShowsPendingAndStreamingBeforeCompletion(t *testing.T) {
	received, headers, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
	// 测试失败也要解除上游等待，避免 httptest.Close 挂起。
	defer func() {
		select {
		case <-finish:
		default:
			close(finish)
		}
		select {
		case <-headers:
		default:
			close(headers)
		}
	}()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(received)
		select {
		case <-headers:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"part\":1}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-finish:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()
	logs := &RequestLog{}
	logs.SetEnabled(true)
	handler := newTestHandler(t, upstream.URL, &memoryAuditor{failAfter: -1}, nil)
	handler.requestLog = logs
	server := httptest.NewServer(handler)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+responsesPath, strings.NewReader(`{"input":"normal","stream":true}`))
	request.Header.Set("Authorization", "Bearer "+testLocalToken)
	request.Header.Set("Content-Type", "application/json")
	firstChunk, done := make(chan error, 1), make(chan error, 1)
	go func() {
		response, err := server.Client().Do(request)
		if err != nil {
			firstChunk <- err
			done <- err
			return
		}
		defer response.Body.Close()
		reader := bufio.NewReader(response.Body)
		line, err := reader.ReadString('\n')
		if err == nil && line != "data: {\"part\":1}\n" {
			err = fmt.Errorf("首段响应被改写: %q", line)
		}
		firstChunk <- err
		_, err = io.ReadAll(reader)
		done <- err
	}()
	select {
	case <-received:
	case <-ctx.Done():
		t.Fatal("上游未收到请求")
	}
	item := logs.Snapshot().Items[0]
	if item.Phase != "forwarding" || item.Status != 0 || item.UpstreamStatus != 0 || item.Finished {
		t.Fatalf("等待响应头时日志状态错误: %+v", item)
	}
	close(headers)
	select {
	case err := <-firstChunk:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("实时采集使 SSE 首段响应无法及时返回")
	}
	item = logs.Snapshot().Items[0]
	if item.Phase != "responding" || item.Status != 200 || item.UpstreamStatus != 200 || !item.Streaming || item.Finished {
		t.Fatalf("流式响应结束前应显示接收中: %+v", item)
	}
	close(finish)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for !logs.Snapshot().Items[0].Finished && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	if item = logs.Snapshot().Items[0]; !item.Finished || item.Phase != "completed" {
		t.Fatalf("响应完成后日志未更新: %+v", item)
	}
}

func TestRequestLogCapturesRejectionsAndUpstreamFailures(t *testing.T) {
	for _, path := range []string{responsesPath, chatCompletionsPath} {
		for _, scenario := range []string{"blocked", "unauthorized", "payload", "upstream", "timeout", "stream", "audit"} {
			t.Run(path+"/"+scenario, func(t *testing.T) {
				logs := &RequestLog{}
				logs.SetEnabled(true)
				auditor := &memoryAuditor{failAfter: -1}
				if scenario == "audit" {
					auditor.failAfter = 0
				}
				handler := newTestHandler(t, "http://127.0.0.1:1", auditor, []storage.Rule{{ID: "customer", Type: "keyword", Enabled: true, Action: security.ActionBlock, Keywords: []string{"客户A"}}})
				handler.requestLog = logs
				handler.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if scenario == "timeout" {
						return nil, context.DeadlineExceeded
					}
					status, header, body := 403, http.Header{"Content-Type": {"application/json"}}, io.NopCloser(strings.NewReader(`{"error":"upstream-response-secret"}`))
					if scenario == "stream" {
						status, header = 200, http.Header{"Content-Type": {"text/event-stream"}}
						body = io.NopCloser(io.MultiReader(strings.NewReader("data: {}\n\n"), iotest.ErrReader(io.ErrUnexpectedEOF)))
					}
					return &http.Response{StatusCode: status, Header: header, Body: body, Request: r}, nil
				})
				text := "body-secret"
				if scenario == "blocked" {
					text = "客户A"
				}
				payload := map[string]any{"input": text}
				if path == chatCompletionsPath {
					payload = map[string]any{"messages": []map[string]string{{"role": "user", "content": text}}}
				}
				if scenario == "payload" {
					payload["model"] = map[string]string{"value": "request-body-secret"}
				}
				raw, _ := json.Marshal(payload)
				request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
				if scenario != "unauthorized" {
					request.Header.Set("Authorization", "Bearer "+testLocalToken)
				}
				request.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				item := logs.Snapshot().Items[0]
				statuses := map[string]int{"blocked": 403, "unauthorized": 401, "payload": 422, "upstream": 403, "timeout": 504, "stream": 200, "audit": 503}
				if item.Status != statuses[scenario] || item.Status != response.Code || !item.Finished || item.RequestID != response.Header().Get("x-gateway-request-id") {
					t.Fatalf("请求返回结果和日志不一致: %+v", item)
				}
				if scenario == "blocked" && (item.Phase != "blocked" || len(item.RuleIDs) != 1 || item.RuleIDs[0] != "customer" || item.UpstreamStatus != 0) {
					t.Fatalf("规则阻断信息错误: %+v", item)
				}
				if scenario == "upstream" && (item.Phase != "failed" || item.UpstreamStatus != 403 ||
					item.ErrorCode != "upstream_http_error" || item.Detail != "上游返回 HTTP 403，错误响应已转发") {
					t.Fatalf("上游拒绝被误报成功: %+v", item)
				}
				if scenario == "stream" && (item.Phase != "failed" || item.ErrorCode != "upstream_error") {
					t.Fatalf("200 状态的流中断被误报成功: %+v", item)
				}
				if scenario == "audit" && item.ErrorCode != "audit_unavailable" {
					t.Fatal("审计不可用时实时日志仍应记录拒绝原因")
				}
				serialized, _ := json.Marshal(item)
				for _, secret := range []string{testLocalToken, "upstream-key", "body-secret", "request-body-secret", "upstream-response-secret"} {
					if strings.Contains(string(serialized), secret) {
						t.Fatalf("实时日志泄露凭证或正文: %s", serialized)
					}
				}
			})
		}
	}
}

func TestRequestLogRedactsClientCredentialsAndDoesNotStoreUnknownURLs(t *testing.T) {
	logs := &RequestLog{}
	logs.SetEnabled(true)
	handler := newClientAuthHandler(t, "http://127.0.0.1:1", &memoryAuditor{failAfter: -1}, nil)
	handler.requestLog = logs
	const secret = "client-live-private-key"
	for _, path := range []string{responsesPath, "/" + secret + "?token=" + secret} {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"input":"normal","type":"input_file-`+secret+`"}`))
		request.Header.Set("Authorization", "Bearer "+secret)
		request.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}
	snapshot := logs.Snapshot()
	serialized, _ := json.Marshal(snapshot)
	if strings.Contains(string(serialized), secret) || snapshot.Items[0].Path != "(不支持的路径)" || !strings.Contains(snapshot.Items[1].Detail, redactedCredential) {
		t.Fatalf("客户端密钥或 URL 未正确脱敏: %s", serialized)
	}
}
