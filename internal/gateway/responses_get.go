package gateway

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/xiaotaowang/prompt-auditing/internal/security"
)

func isResponseRetrievalPath(path string) bool {
	id, ok := strings.CutPrefix(path, responsesPath+"/")
	return ok && len(id) > 0 && len(id) <= 512 && asciiIdentifier(id, false)
}

func asciiIdentifier(value string, dot bool) bool {
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || dot && c == '.') {
			return false
		}
	}
	return value != ""
}

func responseQuery(raw string) (url.Values, error) {
	query, err := url.ParseQuery(raw)
	if err != nil {
		return nil, err
	}
	for key, values := range query {
		if key != "include" && key != "include[]" && len(values) != 1 {
			return nil, strconv.ErrSyntax
		}
		for _, value := range values {
			switch key {
			case "stream", "include_obfuscation":
				if value != "true" && value != "false" {
					return nil, strconv.ErrSyntax
				}
			case "starting_after":
				if _, err := strconv.ParseUint(value, 10, 63); err != nil {
					return nil, err
				}
			case "include", "include[]":
				if len(value) > 256 || !asciiIdentifier(value, true) {
					return nil, strconv.ErrSyntax
				}
			default:
				return nil, strconv.ErrSyntax
			}
		}
	}
	return query, nil
}

func bodylessRequest(request *http.Request) bool {
	return request.ContentLength == 0 && len(request.TransferEncoding) == 0 && strings.TrimSpace(request.Header.Get("Content-Encoding")) == ""
}

func (h *Handler) handleResponseRetrieval(writer http.ResponseWriter, request *http.Request, requestID string, started time.Time) {
	query, err := responseQuery(request.URL.RawQuery)
	if err != nil || !bodylessRequest(request) {
		h.recordRequestRejection(requestID, "unsupported_payload", started, request, http.StatusBadRequest)
		h.reject(writer, http.StatusBadRequest, "unsupported_payload", "响应查询参数无效，或 GET 请求包含正文或请求体编码")
		return
	}
	// 路径及查询字符串也可能携带敏感内容，只允许检测，不能改写响应 ID 或参数。
	body, _ := json.Marshal(map[string]any{"response_id": strings.TrimPrefix(request.URL.Path, responsesPath+"/"), "query": query})
	payload, err := security.Extract(body)
	if err != nil {
		h.recordSystemFailure(requestID, "unsupported_payload", started)
		h.reject(writer, http.StatusBadRequest, "unsupported_payload", "响应查询参数无法检测")
		return
	}
	decision, _, _, failure := h.preparePayload(request.Context(), requestID, started, payload, body, "", security.Marshal)
	if failure != nil {
		h.reject(writer, failure.status, failure.code, failure.message)
		return
	}
	h.forward(writer, request, requestID, started, decision, nil, false)
}
