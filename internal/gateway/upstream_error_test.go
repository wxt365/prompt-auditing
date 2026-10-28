package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/security"
)

func TestUpstreamErrorProcessingFailuresRemainDistinct(t *testing.T) {
	for _, test := range []struct {
		name, body, encoding, result string
		writeFails                   bool
	}{
		{name: "无效 JSON", body: `{`, result: "upstream_error"},
		{name: "损坏的 gzip", body: "probe_invalid_gzip_92", encoding: "gzip", result: "upstream_error"},
		{name: "客户端写入失败", body: `{"error":"probe_error_92"}`, result: "upstream_stream_error", writeFails: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			auditor := &memoryAuditor{failAfter: -1}
			handler := newTestHandler(t, "https://example.invalid", auditor, nil)
			response := &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     http.Header{"Content-Type": {"application/json"}},
				Body:       io.NopCloser(strings.NewReader(test.body)),
			}
			if test.encoding != "" {
				response.Header.Set("Content-Encoding", test.encoding)
			}
			defer response.Body.Close()
			recorder := httptest.NewRecorder()
			var writer http.ResponseWriter = recorder
			if test.writeFails {
				writer = upstreamErrorFailingWriter{recorder}
			}
			handler.forwardUpstreamError(context.Background(), writer, response, "probe_request_92", time.Now(), security.Decision{Action: security.ActionAllow})
			if recorder.Code != response.StatusCode || len(auditor.events) != 1 {
				t.Fatalf("响应状态或完成事件数量错误: status=%d events=%d", recorder.Code, len(auditor.events))
			}
			event := auditor.events[0]
			if event.EventType != "completion" || event.Result != test.result || event.ErrorCode != "upstream_error" ||
				event.UpstreamStatus == nil || *event.UpstreamStatus != response.StatusCode {
				t.Fatalf("上游错误处理失败被错误分类: %+v", event)
			}
		})
	}
}

type upstreamErrorFailingWriter struct {
	*httptest.ResponseRecorder
}

func (upstreamErrorFailingWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}
