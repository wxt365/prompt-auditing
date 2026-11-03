package gateway

import (
	"net/http"
	"strings"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/security"
)

func (h *Handler) handleModels(writer http.ResponseWriter, request *http.Request, requestID string, started time.Time) {
	// 模型发现没有待审计的 Prompt，不接收或转发正文、压缩和分块上传。
	if request.ContentLength != 0 || len(request.TransferEncoding) != 0 || strings.TrimSpace(request.Header.Get("Content-Encoding")) != "" {
		h.recordRequestRejection(requestID, "unsupported_payload", started, request, http.StatusBadRequest)
		h.reject(writer, http.StatusBadRequest, "unsupported_payload", "模型列表请求不得包含正文或请求体编码")
		return
	}
	if !h.audit.Healthy() {
		h.reject(writer, http.StatusServiceUnavailable, "audit_unavailable", "审计服务不可用")
		return
	}
	decision := security.Decision{Action: security.ActionAllow}
	event := h.decisionEvent(requestID, decision, started)
	event.Result = "forwarding"
	event.RequestMethod, event.RequestPath = request.Method, h.requestPath
	if err := h.audit.Write(event); err != nil {
		h.audit.MarkUnhealthy()
		h.reject(writer, http.StatusServiceUnavailable, "audit_unavailable", "审计服务不可用")
		return
	}
	h.trace.update(func(e *RequestLogEntry) { e.Action = security.ActionAllow })
	h.forward(writer, request, requestID, started, decision, nil, false)
}
