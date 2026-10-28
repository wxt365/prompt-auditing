package gateway

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/audit"
	"github.com/xiaotaowang/prompt-auditing/internal/config"
	"github.com/xiaotaowang/prompt-auditing/internal/security"
)

const responsesPath = "/v1/responses"
const chatCompletionsPath = "/v1/chat/completions"

const redactedCredential = "[REDACTED_GATEWAY_CREDENTIAL]"

const securityInspectionTimeout = 2 * time.Second

var (
	errCompressedTooLarge   = errors.New("压缩请求体超过限制")
	errDecompressedTooLarge = errors.New("解压请求体超过限制")
	requestIDFallbackCount  atomic.Uint64
)

type Auditor interface {
	Write(audit.Event) error
	Healthy() bool
	MarkUnhealthy()
}

type SecurityEngine interface {
	RuleSetVersion() string
	Inspect(context.Context, security.Payload) (security.Decision, error)
	ApplyMask(security.Payload, security.Decision) error
}

type Options struct {
	Upstream     *url.URL
	Client       *http.Client
	Engine       SecurityEngine
	Audit        Auditor
	LocalToken   string
	UpstreamKey  string
	ClientAuth   bool
	PayloadError func(string)
	RequestLog   *RequestLog
	Limits       config.LimitsConfig
	OSUser       string
	Now          func() time.Time
}

type Handler struct {
	upstream     *url.URL
	client       *http.Client
	engine       SecurityEngine
	audit        Auditor
	localToken   string
	upstreamKey  string
	clientAuth   bool
	payloadError func(string)
	requestLog   *RequestLog
	trace        *requestTrace
	limits       config.LimitsConfig
	semaphore    chan struct{}
	osUser       string
	now          func() time.Time
}

func NewHandler(options Options) (*Handler, error) {
	if options.Upstream == nil || options.Upstream.Host == "" ||
		(options.Upstream.Scheme != "http" && options.Upstream.Scheme != "https") {
		return nil, errors.New("上游地址无效")
	}
	if options.Client == nil || options.Engine == nil || options.Audit == nil {
		return nil, errors.New("Gateway 依赖不能为空")
	}
	if !options.ClientAuth && (options.LocalToken == "" || options.UpstreamKey == "") {
		return nil, errors.New("本地令牌和上游 API Key 不能为空")
	}
	if !options.ClientAuth && options.LocalToken == options.UpstreamKey {
		return nil, errors.New("本地令牌和上游 API Key 必须使用不同值")
	}
	if options.Limits.MaxCompressedBytes <= 0 || options.Limits.MaxDecompressedBytes <= 0 || options.Limits.MaxConcurrent <= 0 {
		return nil, errors.New("Gateway 请求限制无效")
	}
	if options.OSUser == "" {
		current, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("读取当前 OS 用户失败: %w", err)
		}
		if current.Username == "" {
			return nil, errors.New("当前 OS 用户名为空")
		}
		options.OSUser = current.Username
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	client := *options.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Handler{
		upstream: options.Upstream, client: &client, engine: options.Engine, audit: options.Audit,
		localToken: options.LocalToken, upstreamKey: options.UpstreamKey, clientAuth: options.ClientAuth, payloadError: options.PayloadError, limits: options.Limits,
		requestLog: options.RequestLog,
		semaphore:  make(chan struct{}, options.Limits.MaxConcurrent), osUser: options.OSUser, now: options.Now,
	}, nil
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	requestID := newRequestID()
	writer.Header().Set("x-gateway-request-id", requestID)
	started := h.now()
	if trace := h.requestLog.begin(requestID, request.Method, request.URL.Path); trace != nil {
		current := *h
		current.trace = trace
		h = &current
	}
	returned := false
	defer func() { h.trace.finish(returned, request.Context().Err() != nil) }()
	h.serveRequest(writer, request, requestID, started)
	returned = true
}

func (h *Handler) serveRequest(writer http.ResponseWriter, request *http.Request, requestID string, started time.Time) {
	if request.URL.Path == "/healthz" && request.Method == http.MethodGet {
		h.handleHealth(writer)
		return
	}
	if !h.authorized(request) {
		h.recordSystemFailure(requestID, "gateway_unauthorized", started)
		h.reject(writer, http.StatusUnauthorized, "gateway_unauthorized", "请求认证信息缺失或无效")
		return
	}
	if h.clientAuth {
		// 凭证仅保留在当前请求副本中，供转发及审计脱敏使用，避免并发请求串用密钥。
		current := *h
		current.localToken = clientBearer(request)
		current.upstreamKey = current.localToken
		h = &current
	}
	if (request.URL.Path != responsesPath && request.URL.Path != chatCompletionsPath) || request.URL.RawQuery != "" {
		h.recordSystemFailure(requestID, "gateway_route_not_supported", started)
		h.reject(writer, http.StatusNotFound, "gateway_route_not_supported", "请求路径不受支持")
		return
	}
	if request.Method != http.MethodPost {
		h.recordSystemFailure(requestID, "gateway_route_not_supported", started)
		h.reject(writer, http.StatusMethodNotAllowed, "gateway_route_not_supported", "请求方法不受支持")
		return
	}
	if isUpgradeRequest(request) {
		h.recordSystemFailure(requestID, "gateway_route_not_supported", started)
		h.reject(writer, http.StatusBadRequest, "gateway_route_not_supported", "协议升级不受支持")
		return
	}
	select {
	case h.semaphore <- struct{}{}:
		defer func() { <-h.semaphore }()
	default:
		h.recordSystemFailure(requestID, "gateway_busy", started)
		h.reject(writer, http.StatusTooManyRequests, "gateway_busy", "Gateway 并发请求已达上限")
		return
	}

	h.trace.phase("reading")
	original, decoded, encoding, err := h.readRequestBody(request)
	if err != nil {
		code, message, status := bodyError(err)
		h.recordSystemFailure(requestID, code, started)
		h.reject(writer, status, code, message)
		return
	}
	contentTypes := request.Header.Values("Content-Type")
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if len(contentTypes) != 1 || err != nil || mediaType != "application/json" {
		h.recordSystemFailure(requestID, "unsupported_media_type", started)
		h.reject(writer, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type 不受支持")
		return
	}
	var payload security.Payload
	if request.URL.Path == chatCompletionsPath {
		payload, err = security.ExtractChatCompletions(decoded)
	} else {
		payload, err = security.Extract(decoded)
	}
	if err != nil {
		h.recordSystemFailure(requestID, "unsupported_payload", started)
		detail := redactCredentialString(err.Error(), []string{h.localToken, h.upstreamKey})
		if len(detail) > 512 {
			detail = string([]rune(detail)[:min(128, len([]rune(detail)))]) + "…"
		}
		if h.payloadError != nil {
			h.payloadError(detail)
		}
		h.reject(writer, http.StatusUnprocessableEntity, "unsupported_payload", "请求载荷包含未支持的结构: "+detail)
		return
	}

	h.trace.phase("inspecting")
	inspectionContext, cancelInspection := context.WithTimeout(request.Context(), securityInspectionTimeout)
	decision, err := inspectSafely(inspectionContext, h.engine, payload)
	cancelInspection()
	if err != nil {
		h.recordSystemFailure(requestID, "security_engine_unavailable", started)
		h.reject(writer, http.StatusServiceUnavailable, "security_engine_unavailable", "安全检测服务不可用")
		return
	}
	h.trace.update(func(e *RequestLogEntry) {
		e.Action = decision.Action
		ids := uniqueMatches(decision.Matches, func(match security.Match) string { return match.RuleID })
		for _, id := range ids[:min(20, len(ids))] {
			e.RuleIDs = append(e.RuleIDs, limitLogText(redactCredentialString(id, []string{h.localToken, h.upstreamKey})))
		}
		names := uniqueMatches(decision.Matches, func(match security.Match) string { return match.RuleName })
		for _, name := range names[:min(20, len(names))] {
			e.RuleNames = append(e.RuleNames, limitLogText(redactCredentialString(name, []string{h.localToken, h.upstreamKey})))
		}
	})
	if !h.audit.Healthy() {
		h.reject(writer, http.StatusServiceUnavailable, "audit_unavailable", "审计服务不可用")
		return
	}
	decisionEvent := h.decisionEvent(requestID, decision, started)
	if decision.Action == security.ActionBlock {
		decisionEvent.Result = "blocked"
		decisionEvent.RequestBody, err = auditRequestBody(payload.Root, h.localToken, h.upstreamKey)
		if err != nil {
			h.recordSystemFailure(requestID, "security_engine_unavailable", started)
			h.reject(writer, http.StatusServiceUnavailable, "security_engine_unavailable", "安全检测服务不可用")
			return
		}
		if err := h.audit.Write(decisionEvent); err != nil {
			h.audit.MarkUnhealthy()
			h.reject(writer, http.StatusServiceUnavailable, "audit_unavailable", "审计服务不可用")
			return
		}
		h.reject(writer, http.StatusForbidden, "prompt_blocked", "内容审计命中风险规则，请调整输入后重试")
		return
	}

	forwardBody := original
	bodyModified := false
	if decision.Action == security.ActionMask {
		if err := applyMaskSafely(h.engine, payload, decision); err != nil {
			h.recordSystemFailure(requestID, "security_engine_unavailable", started)
			h.reject(writer, http.StatusServiceUnavailable, "security_engine_unavailable", "安全检测服务不可用")
			return
		}
		masked, err := security.Marshal(payload)
		if err != nil {
			h.recordSystemFailure(requestID, "security_engine_unavailable", started)
			h.reject(writer, http.StatusServiceUnavailable, "security_engine_unavailable", "安全检测服务不可用")
			return
		}
		forwardBody, err = encodeBody(masked, encoding)
		if err != nil {
			h.recordSystemFailure(requestID, "security_engine_unavailable", started)
			h.reject(writer, http.StatusServiceUnavailable, "security_engine_unavailable", "安全检测服务不可用")
			return
		}
		bodyModified = !bytes.Equal(forwardBody, original)
	}
	decisionEvent.Result = "forwarding"
	if err := h.audit.Write(decisionEvent); err != nil {
		h.audit.MarkUnhealthy()
		h.reject(writer, http.StatusServiceUnavailable, "audit_unavailable", "审计服务不可用")
		return
	}
	h.forward(writer, request, requestID, started, decision, forwardBody, bodyModified)
}

func isUpgradeRequest(request *http.Request) bool {
	if strings.TrimSpace(request.Header.Get("Upgrade")) != "" {
		return true
	}
	for _, value := range request.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

func inspectSafely(ctx context.Context, engine SecurityEngine, payload security.Payload) (decision security.Decision, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("安全检测异常: %v", recovered)
		}
	}()
	return engine.Inspect(ctx, payload)
}

func applyMaskSafely(engine SecurityEngine, payload security.Payload, decision security.Decision) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("安全脱敏异常: %v", recovered)
		}
	}()
	return engine.ApplyMask(payload, decision)
}

func (h *Handler) handleHealth(writer http.ResponseWriter) {
	status := http.StatusOK
	state := "ok"
	if !h.audit.Healthy() {
		status = http.StatusServiceUnavailable
		state = "unavailable"
	}
	writer.Header().Set("Content-Type", "application/json")
	h.trace.status(status)
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"status": state, "rule_set_version": h.engine.RuleSetVersion(), "policy": true, "audit": h.audit.Healthy(),
	})
}

func (h *Handler) authorized(request *http.Request) bool {
	if h.clientAuth {
		// 透传模式由固定上游验证凭证，本地仅检查认证头格式。
		return clientBearer(request) != ""
	}
	provided := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	if provided == request.Header.Get("Authorization") || len(provided) != len(h.localToken) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(h.localToken)) == 1
}

func clientBearer(request *http.Request) string {
	if len(request.Header.Values("Authorization")) != 1 {
		return ""
	}
	parts := strings.Fields(request.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

func (h *Handler) readRequestBody(request *http.Request) ([]byte, []byte, string, error) {
	if len(request.Header.Values("Content-Encoding")) > 1 {
		return nil, nil, "", errors.New("Content-Encoding 不得重复")
	}
	encoding := strings.ToLower(strings.TrimSpace(request.Header.Get("Content-Encoding")))
	if encoding != "" && encoding != "gzip" {
		return nil, nil, encoding, fmt.Errorf("不支持的 Content-Encoding: %s", encoding)
	}
	if request.ContentLength > h.limits.MaxCompressedBytes {
		return nil, nil, encoding, errCompressedTooLarge
	}
	original, err := readLimited(request.Body, h.limits.MaxCompressedBytes)
	if err != nil {
		return nil, nil, encoding, err
	}
	if encoding == "" {
		return original, original, encoding, nil
	}
	reader, err := gzip.NewReader(bytes.NewReader(original))
	if err != nil {
		return nil, nil, encoding, fmt.Errorf("gzip 请求体无效: %w", err)
	}
	defer reader.Close()
	decoded, err := readLimited(reader, h.limits.MaxDecompressedBytes)
	if errors.Is(err, errCompressedTooLarge) {
		return nil, nil, encoding, errDecompressedTooLarge
	}
	if err != nil {
		return nil, nil, encoding, fmt.Errorf("读取 gzip 请求体: %w", err)
	}
	return original, decoded, encoding, nil
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errCompressedTooLarge
	}
	return data, nil
}

func bodyError(err error) (string, string, int) {
	if errors.Is(err, errCompressedTooLarge) || errors.Is(err, errDecompressedTooLarge) {
		return "payload_too_large", "请求体超过大小限制", http.StatusRequestEntityTooLarge
	}
	return "unsupported_media_type", "Content-Encoding 或压缩请求体不受支持", http.StatusUnsupportedMediaType
}

func encodeBody(decoded []byte, encoding string) ([]byte, error) {
	if encoding == "" {
		return decoded, nil
	}
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(decoded); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func auditRequestBody(root any, secrets ...string) (json.RawMessage, error) {
	body, err := json.Marshal(redactCredentials(root, secrets))
	if err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

func redactCredentials(value any, secrets []string) any {
	switch current := value.(type) {
	case string:
		return redactCredentialString(current, secrets)
	case []any:
		result := make([]any, len(current))
		for index, item := range current {
			result[index] = redactCredentials(item, secrets)
		}
		return result
	case map[string]any:
		result := make(map[string]any, len(current))
		for key, item := range current {
			redactedKey := redactCredentialString(key, secrets)
			for suffix := 1; ; suffix++ {
				if _, exists := result[redactedKey]; !exists {
					break
				}
				redactedKey = fmt.Sprintf("%s#%d", redactedKey, suffix)
			}
			result[redactedKey] = redactCredentials(item, secrets)
		}
		return result
	default:
		return current
	}
}

func redactCredentialString(value string, secrets []string) string {
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, redactedCredential)
		}
	}
	return value
}

func (h *Handler) decisionEvent(requestID string, decision security.Decision, started time.Time) audit.Event {
	event := audit.Event{
		EventType: "decision", RequestID: requestID, User: h.osUser,
		RuleSetVersion: h.engine.RuleSetVersion(), RuleIDs: uniqueMatches(decision.Matches, func(match security.Match) string { return match.RuleID }),
		Categories:      uniqueMatches(decision.Matches, func(match security.Match) string { return match.Category }),
		MatchedKeywords: matchedKeywords(decision.Matches), MatchCount: len(decision.Matches),
		Action: decision.Action, DurationMS: h.now().Sub(started).Milliseconds(), Matches: auditMatches(decision.Matches),
	}
	secrets := []string{h.localToken, h.upstreamKey}
	for index := range event.MatchedKeywords {
		event.MatchedKeywords[index] = redactCredentialString(event.MatchedKeywords[index], secrets)
	}
	for index := range event.Matches {
		event.Matches[index].MatchedKeyword = redactCredentialString(event.Matches[index].MatchedKeyword, secrets)
		event.Matches[index].RuleName = redactCredentialString(event.Matches[index].RuleName, secrets)
	}
	return event
}

func auditMatches(matches []security.Match) []audit.Match {
	seen := make(map[string]struct{})
	result := make([]audit.Match, 0, len(matches))
	for _, match := range matches {
		keyword := ""
		if match.Category == "keyword" || match.Category == "keyword_mapping" {
			keyword = match.Original
		}
		key := match.RuleID + "\x00" + match.Category + "\x00" + keyword + "\x00" + match.Action + "\x00" + match.BlockReason
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, audit.Match{RuleID: match.RuleID, RuleName: match.RuleName, Category: match.Category, MatchedKeyword: keyword, Action: match.Action, Reason: match.BlockReason})
	}
	return result
}

func uniqueMatches(matches []security.Match, value func(security.Match) string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, match := range matches {
		item := value(match)
		if item == "" {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}

func matchedKeywords(matches []security.Match) []string {
	return uniqueMatches(matches, func(match security.Match) string {
		if match.Category == "keyword" || match.Category == "keyword_mapping" {
			return match.Original
		}
		return ""
	})
}

func (h *Handler) recordSystemFailure(requestID, errorCode string, started time.Time) {
	err := h.audit.Write(audit.Event{
		EventType: "system_error", RequestID: requestID, User: h.osUser,
		RuleSetVersion: h.engine.RuleSetVersion(), Action: "block", Result: "rejected",
		ErrorCode: errorCode, DurationMS: h.now().Sub(started).Milliseconds(),
	})
	if err != nil {
		h.audit.MarkUnhealthy()
		h.trace.update(func(e *RequestLogEntry) { e.AuditError = true })
	}
}

func newRequestID() string {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return fmt.Sprintf("req_fallback_%d_%d_%d", os.Getpid(), time.Now().UnixNano(), requestIDFallbackCount.Add(1))
	}
	return "req_" + hex.EncodeToString(random)
}

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Message string  `json:"message"`
	Type    string  `json:"type"`
	Param   *string `json:"param"`
	Code    string  `json:"code"`
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(errorEnvelope{Error: errorBody{
		Message: message, Type: errorType(code), Code: code,
	}})
}

func errorType(code string) string {
	if code == "prompt_blocked" {
		return "security_policy_violation"
	}
	return "gateway_error"
}

func timeoutStatus(err error) int {
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return http.StatusGatewayTimeout
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}
