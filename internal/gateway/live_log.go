package gateway

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

const requestLogCapacity = 500

type RequestLogEntry struct {
	ID             uint64    `json:"id"`
	RequestID      string    `json:"request_id"`
	ReceivedAt     time.Time `json:"received_at"`
	Method         string    `json:"method"`
	Path           string    `json:"path"`
	Phase          string    `json:"phase"`
	Status         int       `json:"status"`
	UpstreamStatus int       `json:"upstream_status"`
	DurationMS     int64     `json:"duration_ms"`
	HeaderMS       int64     `json:"header_ms"`
	Streaming      bool      `json:"streaming"`
	Action         string    `json:"action"`
	RuleIDs        []string  `json:"rule_ids,omitempty"`
	RuleNames      []string  `json:"rule_names,omitempty"`
	ErrorCode      string    `json:"error_code"`
	Detail         string    `json:"detail"`
	AuditError     bool      `json:"audit_error"`
	Finished       bool      `json:"finished"`
}

type RequestLogSnapshot struct {
	Enabled  bool              `json:"enabled"`
	Capacity int               `json:"capacity"`
	Dropped  uint64            `json:"dropped"`
	Items    []RequestLogEntry `json:"items"`
}

// 仅保存有界的请求元信息，与持久化审计和响应传输相互独立。
type RequestLog struct {
	mu          sync.Mutex
	enabled     bool
	generation  uint64
	sequence    uint64
	dropped     uint64
	entries     [requestLogCapacity]*requestTrace
	next, count int
}

type requestTrace struct {
	log        *RequestLog
	generation uint64
	entry      RequestLogEntry
}

func (l *RequestLog) SetEnabled(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.enabled == enabled {
		return
	}
	l.enabled = enabled
	l.generation++
	if !enabled {
		for _, trace := range l.entries {
			if trace != nil && !trace.entry.Finished {
				trace.entry.Phase = "capture_stopped"
				trace.entry.Finished = true
				trace.entry.DurationMS = time.Since(trace.entry.ReceivedAt).Milliseconds()
			}
		}
	}
}

func (l *RequestLog) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.generation++
	l.entries = [requestLogCapacity]*requestTrace{}
	l.next, l.count, l.dropped = 0, 0, 0
}

func (l *RequestLog) Snapshot() RequestLogSnapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	result := RequestLogSnapshot{Enabled: l.enabled, Capacity: requestLogCapacity, Dropped: l.dropped, Items: make([]RequestLogEntry, 0, l.count)}
	for i := 0; i < l.count; i++ {
		entry := l.entries[(l.next-1-i+requestLogCapacity)%requestLogCapacity].entry
		entry.RuleIDs = append([]string(nil), entry.RuleIDs...)
		entry.RuleNames = append([]string(nil), entry.RuleNames...)
		if !entry.Finished {
			entry.DurationMS = time.Since(entry.ReceivedAt).Milliseconds()
		}
		result.Items = append(result.Items, entry)
	}
	return result
}

func (l *RequestLog) begin(requestID, method, path string) *requestTrace {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.enabled {
		return nil
	}
	// 未知路径不保留原文，避免将 URL 中误填的凭证写入调试日志。
	if !supportedRequestPath(path) && path != chatCompletionsAliasPath && path != "/healthz" {
		path = "(不支持的路径)"
	}
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead, http.MethodOptions, http.MethodConnect, http.MethodTrace:
	default:
		method = "OTHER"
	}
	l.sequence++
	trace := &requestTrace{log: l, generation: l.generation, entry: RequestLogEntry{
		ID: l.sequence, RequestID: requestID, ReceivedAt: time.Now(), Method: method, Path: path, Phase: "received",
	}}
	l.entries[l.next] = trace
	l.next = (l.next + 1) % requestLogCapacity
	if l.count < requestLogCapacity {
		l.count++
	} else {
		l.dropped++
	}
	return trace
}

func (t *requestTrace) update(change func(*RequestLogEntry)) {
	if t == nil {
		return
	}
	t.log.mu.Lock()
	defer t.log.mu.Unlock()
	if t.log.enabled && t.generation == t.log.generation && !t.entry.Finished {
		change(&t.entry)
	}
}

func (t *requestTrace) phase(phase string) {
	t.update(func(e *RequestLogEntry) { e.Phase = phase })
}

func (t *requestTrace) status(status int) {
	t.update(func(e *RequestLogEntry) { e.Status = status })
}

func (t *requestTrace) failure(code, detail string) {
	t.update(func(e *RequestLogEntry) { e.ErrorCode, e.Detail = code, limitLogText(detail) })
}

func (t *requestTrace) finish(returned, canceled bool) {
	t.update(func(e *RequestLogEntry) {
		e.DurationMS = time.Since(e.ReceivedAt).Milliseconds()
		e.Finished = true
		switch {
		case !returned:
			e.Phase, e.ErrorCode = "failed", "handler_aborted"
		case canceled || e.ErrorCode == "client_canceled":
			e.Phase = "interrupted"
			if e.ErrorCode == "" {
				e.ErrorCode = "client_canceled"
			}
		case e.ErrorCode == "prompt_blocked":
			e.Phase = "blocked"
		case strings.HasPrefix(e.ErrorCode, "upstream_") || e.Status >= 500 || e.UpstreamStatus >= 400:
			e.Phase = "failed"
		case e.Status >= 400:
			e.Phase = "rejected"
		default:
			e.Phase = "completed"
		}
	})
}

func limitLogText(value string) string {
	runes := []rune(value)
	if len(runes) > 512 {
		return string(runes[:512]) + "…"
	}
	return value
}

func (h *Handler) reject(writer http.ResponseWriter, status int, code, message string) {
	h.trace.status(status)
	h.trace.failure(code, redactCredentialString(message, []string{h.localToken, h.upstreamKey}))
	writeError(writer, status, code, message)
}
