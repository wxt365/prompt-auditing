package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/security"
)

type ActiveRequest struct {
	RequestID     string `json:"request_id"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	SessionID     string `json:"session_id"`
	SessionSource string `json:"session_source"`
	Protocol      string `json:"protocol"`
	Phase         string `json:"phase"`
	DurationMS    int64  `json:"duration_ms"`
	started       time.Time
}

type SessionConcurrency struct {
	SessionID string `json:"session_id"`
	Current   int    `json:"current"`
	HTTP      int    `json:"http"`
	SSE       int    `json:"sse"`
	WebSocket int    `json:"websocket"`
	LongestMS int64  `json:"longest_ms"`
}

type ConcurrencySnapshot struct {
	Running  bool                 `json:"running"`
	Current  int                  `json:"current"`
	Limit    int                  `json:"limit"`
	Sessions []SessionConcurrency `json:"sessions"`
	Items    []ActiveRequest      `json:"items"`
}

// 独立于日志采集，仅保存正在占用并发名额的有界元信息。
type concurrencyTracker struct {
	mu     sync.Mutex
	key    string
	active map[*ActiveRequest]struct{}
}

func (h *Handler) acquireActivity(request *http.Request, requestID string) bool {
	t := h.concurrency
	t.mu.Lock()
	defer t.mu.Unlock()
	select {
	case h.semaphore <- struct{}{}:
	default:
		return false
	}
	h.activity = &ActiveRequest{RequestID: requestID, Method: h.requestMethod, Path: h.requestPath,
		Protocol: "http", Phase: "received", started: time.Now()}
	if isUpgradeRequest(request) {
		h.activity.Protocol = "websocket"
	}
	t.active[h.activity] = struct{}{}
	for _, name := range []string{"session_id", "X-Session-ID"} {
		for _, value := range request.Header.Values(name) {
			h.identifySessionLocked(value, name)
		}
	}
	return true
}

func (h *Handler) releaseActivity() {
	h.concurrency.mu.Lock()
	defer h.concurrency.mu.Unlock()
	delete(h.concurrency.active, h.activity)
	<-h.semaphore
}

func (h *Handler) identifySessionLocked(value, source string) {
	if h.activity == nil || h.activity.SessionSource == "conflicting" || value == "" {
		return
	}
	// 任意客户端输入都只转换为实例内稳定的匿名标签，不保存原始标识或凭证。
	if len(value) > 256 || !asciiIdentifier(value, true) {
		h.activity.SessionID, h.activity.SessionSource = "", "conflicting"
		return
	}
	mac := hmac.New(sha256.New, []byte(h.concurrency.key))
	mac.Write([]byte(value))
	id := "session-" + hex.EncodeToString(mac.Sum(nil)[:12])
	if h.activity.SessionID != "" && h.activity.SessionID != id {
		h.activity.SessionID, h.activity.SessionSource = "", "conflicting"
		return
	}
	h.activity.SessionID, h.activity.SessionSource = id, source
}

func (h *Handler) identifyPayloadSession(payload security.Payload) {
	if h.activity == nil {
		return
	}
	root, _ := payload.Root.(map[string]any)
	if response, ok := root["response"].(map[string]any); ok {
		root = response
	}
	metadata, _ := root["client_metadata"].(map[string]any)
	value, _ := metadata["session_id"].(string)
	h.concurrency.mu.Lock()
	defer h.concurrency.mu.Unlock()
	h.identifySessionLocked(value, "client_metadata.session_id")
}

func (h *Handler) activityPhase(phase, protocol string) {
	if h.activity == nil || h.webSocketEvent {
		return
	}
	h.concurrency.mu.Lock()
	defer h.concurrency.mu.Unlock()
	h.activity.Phase = phase
	if protocol != "" {
		h.activity.Protocol = protocol
	}
}

func (h *Handler) phase(phase string) {
	h.trace.phase(phase)
	h.activityPhase(phase, "")
}

func (h *Handler) ConcurrencySnapshot() ConcurrencySnapshot {
	t := h.concurrency
	t.mu.Lock()
	defer t.mu.Unlock()
	result := ConcurrencySnapshot{Running: true, Limit: cap(h.semaphore),
		Items: make([]ActiveRequest, 0, len(t.active)), Sessions: []SessionConcurrency{}}
	groups := map[string]*SessionConcurrency{}
	for active := range t.active {
		item := *active
		item.DurationMS = time.Since(item.started).Milliseconds()
		result.Items = append(result.Items, item)
		group := groups[item.SessionID]
		if group == nil {
			group = &SessionConcurrency{SessionID: item.SessionID}
			groups[item.SessionID] = group
		}
		group.Current++
		group.LongestMS = max(group.LongestMS, item.DurationMS)
		switch item.Protocol {
		case "websocket":
			group.WebSocket++
		case "sse":
			group.SSE++
		default:
			group.HTTP++
		}
	}
	result.Current = len(result.Items)
	for _, group := range groups {
		result.Sessions = append(result.Sessions, *group)
	}
	sort.Slice(result.Sessions, func(i, j int) bool { return result.Sessions[i].SessionID < result.Sessions[j].SessionID })
	sort.Slice(result.Items, func(i, j int) bool {
		if result.Items[i].started.Equal(result.Items[j].started) {
			return result.Items[i].RequestID < result.Items[j].RequestID
		}
		return result.Items[i].started.Before(result.Items[j].started)
	})
	return result
}
