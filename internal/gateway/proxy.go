package gateway

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/audit"
	"github.com/xiaotaowang/prompt-auditing/internal/security"
)

var hopByHopHeaders = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Proxy-Connection": true, "Te": true, "Trailer": true,
	"Transfer-Encoding": true, "Upgrade": true,
}

func (h *Handler) forward(writer http.ResponseWriter, incoming *http.Request, requestID string, started time.Time, decision security.Decision, body []byte, bodyModified bool) {
	target := *h.upstream
	basePath := strings.TrimRight(target.Path, "/")
	if strings.HasSuffix(basePath, "/v1") {
		target.Path = basePath + "/responses"
	} else {
		target.Path = basePath + responsesPath
	}
	target.RawQuery = ""
	target.Fragment = ""
	request, err := http.NewRequestWithContext(incoming.Context(), http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		h.complete(requestID, started, decision, nil, "upstream_error", "upstream_error")
		writeError(writer, http.StatusBadGateway, "upstream_error", "无法创建上游请求")
		return
	}
	// 禁止 net/http 将带幂等 Header 的 POST 识别为可重放请求。
	request.GetBody = nil
	copyRequestHeaders(request.Header, incoming.Header)
	if bodyModified {
		for _, name := range []string{"Content-MD5", "Digest", "Etag", "Content-Digest", "Repr-Digest"} {
			request.Header.Del(name)
		}
	}
	request.Header.Set("Authorization", "Bearer "+h.upstreamKey)
	request.Header.Del("Proxy-Authorization")
	request.ContentLength = int64(len(body))
	request.Host = target.Host

	response, err := h.client.Do(request)
	if err != nil {
		status := timeoutStatus(err)
		h.complete(requestID, started, decision, nil, "upstream_error", "upstream_error")
		writeError(writer, status, "upstream_error", "上游连接或超时错误")
		return
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusBadRequest {
		h.forwardUpstreamError(writer, response, requestID, started, decision)
		return
	}
	copyResponseHeaders(writer.Header(), response.Header)
	if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest {
		writer.Header().Del("Location")
	}
	writer.Header().Set("x-gateway-request-id", requestID)
	writer.WriteHeader(response.StatusCode)
	copyError := copyResponse(writer, response.Body)
	result := "completed"
	errorCode := ""
	if copyError != nil {
		result = "upstream_stream_error"
		errorCode = "upstream_error"
	}
	h.complete(requestID, started, decision, &response.StatusCode, result, errorCode)
}

func (h *Handler) forwardUpstreamError(writer http.ResponseWriter, response *http.Response, requestID string, started time.Time, decision security.Decision) {
	body, err := readUpstreamErrorBody(response, h.limits.MaxDecompressedBytes)
	if err == nil {
		body, err = sanitizeUpstreamErrorBody(body, response.Header.Get("Content-Type"), h.localToken, h.upstreamKey)
	}
	copyResponseHeaders(writer.Header(), response.Header)
	sanitizeHeaderCredentials(writer.Header(), h.localToken, h.upstreamKey)
	for _, name := range []string{"Content-Encoding", "Content-Length", "Content-Md5", "Content-Range", "Digest", "Etag"} {
		writer.Header().Del(name)
	}
	writer.Header().Set("x-gateway-request-id", requestID)
	if err != nil {
		writer.Header().Set("Content-Type", "application/json")
		writeError(writer, response.StatusCode, "upstream_error", "上游错误响应无法安全处理")
		h.complete(requestID, started, decision, &response.StatusCode, "upstream_error", "upstream_error")
		return
	}
	writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(response.StatusCode)
	result := "completed"
	errorCode := ""
	if _, err := writer.Write(body); err != nil {
		result = "upstream_stream_error"
		errorCode = "upstream_error"
	}
	h.complete(requestID, started, decision, &response.StatusCode, result, errorCode)
}

func sanitizeHeaderCredentials(header http.Header, secrets ...string) {
	for name, values := range header {
		for index, value := range values {
			for _, secret := range secrets {
				if secret != "" {
					value = strings.ReplaceAll(value, secret, redactedCredential)
				}
			}
			values[index] = value
		}
		header[name] = values
	}
}

func sanitizeUpstreamErrorBody(body []byte, contentType string, secrets ...string) ([]byte, error) {
	mediaType, _, mediaTypeErr := mime.ParseMediaType(contentType)
	jsonDeclared := mediaTypeErr == nil && (mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"))
	if json.Valid(body) {
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		return json.Marshal(redactCredentials(value, secrets))
	}
	if jsonDeclared {
		return nil, errors.New("上游错误响应声明为 JSON 但正文无效")
	}
	for _, secret := range secrets {
		if secret != "" {
			body = bytes.ReplaceAll(body, []byte(secret), []byte(redactedCredential))
		}
	}
	return body, nil
}

func readUpstreamErrorBody(response *http.Response, limit int64) ([]byte, error) {
	if len(response.Header.Values("Content-Encoding")) > 1 {
		return nil, errors.New("上游错误响应包含重复 Content-Encoding")
	}
	var reader io.Reader = response.Body
	var compressed *gzip.Reader
	switch strings.ToLower(strings.TrimSpace(response.Header.Get("Content-Encoding"))) {
	case "":
	case "gzip":
		var err error
		compressed, err = gzip.NewReader(response.Body)
		if err != nil {
			return nil, err
		}
		defer compressed.Close()
		reader = compressed
	default:
		return nil, errors.New("上游错误响应使用不支持的 Content-Encoding")
	}
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("上游错误响应正文超过安全处理上限")
	}
	return body, nil
}

func copyRequestHeaders(target, source http.Header) {
	copyEndToEndHeaders(target, source, true)
}

func copyResponseHeaders(target, source http.Header) {
	copyEndToEndHeaders(target, source, false)
}

func copyEndToEndHeaders(target, source http.Header, request bool) {
	connectionHeaders := make(map[string]bool)
	for _, value := range source.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			connectionHeaders[http.CanonicalHeaderKey(strings.TrimSpace(name))] = true
		}
	}
	for name, values := range source {
		canonical := http.CanonicalHeaderKey(name)
		if hopByHopHeaders[canonical] || connectionHeaders[canonical] {
			continue
		}
		if request && (canonical == "Authorization" || canonical == "Host" || canonical == "Content-Length" ||
			canonical == "Forwarded" || strings.HasPrefix(canonical, "X-Forwarded-")) {
			continue
		}
		for _, value := range values {
			target.Add(canonical, value)
		}
	}
}

type flushingWriter struct {
	writer  io.Writer
	flusher http.Flusher
}

func (w flushingWriter) Write(data []byte) (int, error) {
	written, err := w.writer.Write(data)
	w.flusher.Flush()
	return written, err
}

func copyResponse(writer http.ResponseWriter, source io.Reader) error {
	if flusher, ok := writer.(http.Flusher); ok {
		_, err := io.Copy(flushingWriter{writer: writer, flusher: flusher}, source)
		return err
	}
	_, err := io.Copy(writer, source)
	return err
}

func (h *Handler) complete(requestID string, started time.Time, decision security.Decision, upstreamStatus *int, result, errorCode string) {
	event := audit.Event{
		EventType: "completion", RequestID: requestID, User: h.osUser,
		RuleSetVersion: h.engine.RuleSetVersion(), Action: decision.Action, Result: result,
		UpstreamStatus: upstreamStatus, DurationMS: h.now().Sub(started).Milliseconds(), ErrorCode: errorCode,
	}
	if err := h.audit.Write(event); err != nil {
		h.audit.MarkUnhealthy()
	}
}
