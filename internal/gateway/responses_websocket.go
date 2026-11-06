package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/xiaotaowang/prompt-auditing/internal/security"
)

type webSocketSession struct {
	cancel context.CancelFunc
	done   chan struct{}
}

type webSocketConnections struct {
	mu     sync.Mutex
	closed bool
	active map[*webSocketSession]struct{}
}

// HTTP Server 不管理已升级连接，停止服务时须显式取消这些连接及其转发任务。
func (h *Handler) CloseWebSockets() {
	h.webSockets.mu.Lock()
	h.webSockets.closed = true
	sessions := make([]*webSocketSession, 0, len(h.webSockets.active))
	for session := range h.webSockets.active {
		session.cancel()
		sessions = append(sessions, session)
	}
	h.webSockets.mu.Unlock()
	for _, session := range sessions {
		<-session.done
	}
}

func validWebSocketHandshake(request *http.Request) bool {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(request.Header.Get("Sec-WebSocket-Key")))
	if err != nil || len(key) != 16 || len(request.Header.Values("Sec-WebSocket-Key")) != 1 ||
		request.Header.Get("Sec-WebSocket-Version") != "13" || !request.ProtoAtLeast(1, 1) || !bodylessRequest(request) ||
		!strings.EqualFold(strings.TrimSpace(request.Header.Get("Upgrade")), "websocket") {
		return false
	}
	connectionUpgrade := false
	for _, value := range request.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			connectionUpgrade = connectionUpgrade || strings.EqualFold(strings.TrimSpace(token), "upgrade")
		}
	}
	// 保留同源校验，避免任意网页借本地代理建立长连接。
	if origins := request.Header.Values("Origin"); len(origins) > 0 {
		origin, err := url.Parse(origins[0])
		if len(origins) != 1 || err != nil || (origin.Scheme != "http" && origin.Scheme != "https") || !strings.EqualFold(origin.Host, request.Host) {
			return false
		}
	}
	return connectionUpgrade
}

func (h *Handler) handleResponsesWebSocket(writer http.ResponseWriter, request *http.Request, requestID string, started time.Time) {
	if !validWebSocketHandshake(request) {
		h.recordRequestRejection(requestID, "unsupported_payload", started, request, http.StatusBadRequest)
		h.reject(writer, http.StatusBadRequest, "unsupported_payload", "WebSocket 握手无效，或包含正文、请求体编码或非同源 Origin")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(request.Context()), time.Hour)
	defer cancel()
	session := &webSocketSession{cancel: cancel, done: make(chan struct{})}
	h.webSockets.mu.Lock()
	closing := h.webSockets.closed
	if !closing {
		h.webSockets.active[session] = struct{}{}
	}
	h.webSockets.mu.Unlock()
	if closing {
		h.recordSystemFailure(requestID, "gateway_stopping", started)
		h.reject(writer, http.StatusServiceUnavailable, "gateway_stopping", "Gateway 正在停止")
		return
	}
	defer func() {
		h.webSockets.mu.Lock()
		delete(h.webSockets.active, session)
		h.webSockets.mu.Unlock()
		close(session.done)
	}()
	if !h.audit.Healthy() {
		h.reject(writer, http.StatusServiceUnavailable, "audit_unavailable", "审计服务不可用")
		return
	}
	decision := security.Decision{Action: security.ActionAllow}
	event := h.decisionEvent(requestID, decision, started)
	event.Result, event.RequestMethod, event.RequestPath = "websocket_connecting", request.Method, h.requestPath
	if err := h.audit.Write(event); err != nil {
		h.audit.MarkUnhealthy()
		h.reject(writer, http.StatusServiceUnavailable, "audit_unavailable", "审计服务不可用")
		return
	}
	header := make(http.Header)
	copyRequestHeaders(header, request.Header)
	protocols := []string{}
	for _, value := range header.Values("Sec-WebSocket-Protocol") {
		for _, protocol := range strings.Split(value, ",") {
			if protocol = strings.TrimSpace(protocol); protocol != "" {
				protocols = append(protocols, protocol)
			}
		}
	}
	for name := range header {
		if strings.HasPrefix(strings.ToLower(name), "sec-websocket-") {
			header.Del(name)
		}
	}
	for _, name := range []string{"Origin", "Content-Type", "Content-MD5", "Digest", "Etag", "Content-Digest", "Repr-Digest"} {
		header.Del(name)
	}
	header.Set("Authorization", "Bearer "+h.upstreamKey)
	target := h.upstreamURL(request)
	h.phase("forwarding")
	// 仅握手受 HTTP 请求取消及握手时限约束；连接内读写由会话上下文管理。
	stopClientCancel := context.AfterFunc(request.Context(), cancel)
	dialCtx, dialCancel := context.WithTimeout(ctx, h.upstreamHeaderTimeout)
	upstream, response, err := websocket.Dial(dialCtx, target.String(), &websocket.DialOptions{
		HTTPClient: h.client, HTTPHeader: header, Subprotocols: protocols,
	})
	stopClientCancel()
	dialCancel()
	if err != nil {
		if response != nil && response.Body != nil {
			defer response.Body.Close()
			if response.StatusCode >= 400 {
				h.forwardUpstreamError(request.Context(), writer, response, requestID, started, decision)
				return
			}
		}
		h.complete(requestID, started, decision, nil, "upstream_error", "upstream_error")
		h.reject(writer, http.StatusBadGateway, "upstream_error", "上游不支持 WebSocket，或连接失败")
		return
	}
	defer upstream.CloseNow()
	acceptedProtocols := []string{}
	if upstream.Subprotocol() != "" {
		acceptedProtocols = append(acceptedProtocols, upstream.Subprotocol())
	}
	client, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: acceptedProtocols})
	if err != nil {
		h.recordRequestRejection(requestID, "unsupported_payload", started, request, http.StatusBadRequest)
		h.trace.status(http.StatusBadRequest)
		return
	}
	defer client.CloseNow()
	limit := min(h.limits.MaxCompressedBytes, h.limits.MaxDecompressedBytes)
	// 不协商消息压缩，两端均对重组后的完整消息执行大小限制。
	client.SetReadLimit(limit)
	upstream.SetReadLimit(h.limits.MaxDecompressedBytes)
	h.activityPhase("responding", "websocket")
	h.trace.update(func(e *RequestLogEntry) {
		e.Status, e.UpstreamStatus, e.Streaming, e.Phase = 101, 101, true, "responding"
	})
	type relayResult struct {
		err         error
		independent bool
	}
	done := make(chan relayResult, 1)
	go func() {
		err := h.relayWebSocketResponses(ctx, client, upstream)
		done <- relayResult{err: err, independent: ctx.Err() == nil}
		// 取消两端正在等待的读写，避免上游先断开后客户端读循环悬挂。
		cancel()
	}()
	err = h.inspectWebSocketRequests(ctx, client, upstream)
	cancel()
	_ = client.CloseNow()
	_ = upstream.CloseNow()
	upstreamResult := <-done
	code := ""
	result := "websocket_closed"
	if upstreamResult.independent && upstreamResult.err != nil && !normalWebSocketClose(upstreamResult.err) {
		code, result = "upstream_stream_error", "upstream_stream_error"
	} else if errors.Is(err, websocket.ErrMessageTooBig) {
		code, result = "payload_too_large", "rejected"
	}
	status := http.StatusSwitchingProtocols
	h.complete(requestID, started, decision, &status, result, code)
}

func normalWebSocketClose(err error) bool {
	status := websocket.CloseStatus(err)
	return status == websocket.StatusNormalClosure || status == websocket.StatusGoingAway
}

func writeWebSocket(ctx context.Context, conn *websocket.Conn, body []byte) error {
	writeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return conn.Write(writeCtx, websocket.MessageText, body)
}

func (h *Handler) relayWebSocketResponses(ctx context.Context, client, upstream *websocket.Conn) error {
	for {
		typ, body, err := upstream.Read(ctx)
		if err != nil {
			return err
		}
		var event struct {
			Type string `json:"type"`
		}
		if typ != websocket.MessageText || json.Unmarshal(body, &event) != nil {
			return errors.New("上游 WebSocket 事件无效")
		}
		if event.Type == "error" || event.Type == "response.failed" {
			body, err = sanitizeUpstreamErrorBody(body, "application/json", h.localToken, h.upstreamKey)
			if err != nil {
				return err
			}
		}
		if !h.audit.Healthy() {
			return errors.New("审计服务不可用")
		}
		if err := writeWebSocket(ctx, client, body); err != nil {
			return err
		}
	}
}

func (h *Handler) inspectWebSocketRequests(ctx context.Context, client, upstream *websocket.Conn) error {
	for {
		typ, body, err := client.Read(ctx)
		if err != nil {
			return err
		}
		if !h.processWebSocketEvent(ctx, client, upstream, typ, body) {
			return nil
		}
	}
}

func (h *Handler) processWebSocketEvent(ctx context.Context, client, upstream *websocket.Conn, typ websocket.MessageType, body []byte) bool {
	requestID, started := newRequestID(), h.now()
	current := *h
	// 事件共用外层连接的名额，仅关联 Session，不覆盖连接的处理阶段。
	current.webSocketEvent = true
	current.trace = h.requestLog.begin(requestID, http.MethodGet, h.requestPath)
	h = &current
	defer func() { h.trace.finish(true, ctx.Err() != nil) }()
	payload, err := security.Extract(body)
	var failure *requestFailure
	var decision security.Decision
	var forward []byte
	var streamID string
	if err != nil || typ != websocket.MessageText {
		failure = &requestFailure{422, "unsupported_payload", "WebSocket 事件必须是受支持的 JSON 文本"}
	} else {
		root := payload.Root.(map[string]any)
		streamID, _ = root["stream_id"].(string)
		if streamID != "" && (len(streamID) > 256 || !asciiIdentifier(streamID, true)) {
			streamID = ""
			failure = &requestFailure{422, "unsupported_payload", "WebSocket stream_id 无效"}
		} else if root["type"] != "response.create" && root["type"] != "response.steer" {
			failure = &requestFailure{422, "unsupported_payload", "WebSocket 客户端事件类型不受支持"}
		}
	}
	if failure != nil {
		h.recordSystemFailure(requestID, failure.code, started)
	} else {
		decision, forward, _, failure = h.preparePayload(ctx, requestID, started, payload, body, "", security.Marshal)
	}
	if failure != nil {
		h.trace.status(failure.status)
		h.trace.failure(failure.code, failure.message)
		event := map[string]any{
			"type": "error", "status": failure.status, "request_id": requestID,
			"error": errorBody{Message: failure.message, Type: errorType(failure.code), Code: failure.code},
		}
		if streamID != "" {
			event["stream_id"] = redactCredentialString(streamID, []string{h.localToken, h.upstreamKey})
		}
		response, _ := json.Marshal(event)
		return writeWebSocket(ctx, client, response) == nil && h.audit.Healthy() && failure.status < 500
	}
	h.phase("forwarding")
	status := http.StatusSwitchingProtocols
	if err := writeWebSocket(ctx, upstream, forward); err != nil {
		h.complete(requestID, started, decision, &status, "upstream_stream_error", "upstream_stream_error")
		return false
	}
	// 此记录只表示事件已发往上游，不把它误记成模型生成完成。
	h.complete(requestID, started, decision, &status, "websocket_forwarded", "")
	h.trace.status(status)
	return h.audit.Healthy()
}
