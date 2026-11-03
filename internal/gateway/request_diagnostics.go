package gateway

import (
	"net/http"
	"net/url"
	"strings"
)

func diagnosticMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead, http.MethodOptions, http.MethodConnect, http.MethodTrace:
		return method
	default:
		return "OTHER"
	}
}

// 仅记录接口路径；移除查询参数，并隐藏已知凭证、疑似密钥及非常规路径片段。
func diagnosticPath(path string, secrets ...string) string {
	path = redactCredentialString(path, secrets)
	for range 3 {
		decoded, err := url.PathUnescape(path)
		if err != nil || decoded == path {
			break
		}
		path = decoded
	}
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	path = redactCredentialString(path, secrets)
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		lower := strings.ToLower(segment)
		hide := len(segment) >= 32 || strings.Contains(segment, redactedCredential) ||
			strings.Contains(lower, "sk-") || strings.Contains(lower, "bearer") || strings.HasPrefix(lower, "eyj")
		if i > 0 {
			switch strings.ToLower(segments[i-1]) {
			case "key", "api_key", "api-key", "token", "access_token", "refresh_token", "password", "secret", "authorization":
				hide = true
			}
		}
		for _, char := range segment {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("-_.", char)) {
				hide = true
			}
		}
		if hide {
			segments[i] = redactedCredential
		}
	}
	return limitLogText(strings.Join(segments, "/"))
}
