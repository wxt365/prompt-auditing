package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xiaotaowang/prompt-auditing/internal/gateway"
	"github.com/xiaotaowang/prompt-auditing/internal/settings"
)

func TestManagementRequiresSessionAndRejectsForeignOrigins(t *testing.T) {
	const origin = "http://127.0.0.1:38123"
	controller := &desktopController{token: "private-client-token"}
	handler := controller.managementHandler(origin, "private-management-session")
	for _, test := range []struct {
		name, host, origin, authorization string
		status                            int
	}{
		{"缺少认证", "127.0.0.1:38123", "", "", http.StatusUnauthorized},
		{"错误令牌", "127.0.0.1:38123", "", "Bearer wrong", http.StatusUnauthorized},
		{"缺少 Bearer 前缀", "127.0.0.1:38123", "", "private-management-session", http.StatusUnauthorized},
		{"外部来源", "127.0.0.1:38123", "https://example.invalid", "Bearer private-management-session", http.StatusForbidden},
		{"域名重绑定", "example.invalid:38123", "", "Bearer private-management-session", http.StatusForbidden},
		{"合法管理请求", "127.0.0.1:38123", origin, "Bearer private-management-session", http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, origin+"/api/token", nil)
			request.Host = test.host
			request.Header.Set("Origin", test.origin)
			request.Header.Set("Authorization", test.authorization)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("状态码=%d，期望%d", response.Code, test.status)
			}
			if test.status != http.StatusOK && strings.Contains(response.Body.String(), controller.token) {
				t.Fatal("拒绝响应泄露本地令牌")
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("管理响应不应被缓存")
			}
		})
	}
}

func TestManagementServesLogoWithLocalImagePolicy(t *testing.T) {
	const origin = "http://127.0.0.1:38123"
	handler := (&desktopController{}).managementHandler(origin, "session")
	request := httptest.NewRequest(http.MethodGet, origin+"/logo.svg", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.HasPrefix(response.Header().Get("Content-Type"), "image/svg+xml") || !strings.Contains(response.Body.String(), "<svg") {
		t.Fatal("内置图标未作为 SVG 正确提供")
	}
	if !strings.Contains(response.Header().Get("Content-Security-Policy"), "img-src 'self';") {
		t.Fatal("页面策略未允许加载本机图标")
	}
}

func TestManagementLiveLogsControlsAndAuthentication(t *testing.T) {
	const origin = "http://127.0.0.1:38123"
	controller := &desktopController{}
	handler := controller.managementHandler(origin, "session")
	for _, test := range []struct {
		method, body, authorization, requestOrigin string
		status                                     int
		enabled                                    bool
	}{
		{http.MethodGet, "", "", "", 401, false},
		{http.MethodPut, `{"enabled":true}`, "Bearer session", "https://foreign.invalid", 403, false},
		{http.MethodGet, "", "Bearer session", origin, 200, false},
		{http.MethodPut, `{}`, "Bearer session", origin, 400, false},
		{http.MethodPut, `{"enabled":true}`, "Bearer session", origin, 200, true},
		{http.MethodDelete, "", "Bearer session", origin, 200, true},
		{http.MethodPut, `{"enabled":false}`, "Bearer session", origin, 200, false},
		{http.MethodGet, "", "Bearer session", origin, 200, false},
	} {
		request := httptest.NewRequest(test.method, origin+"/api/live-logs", strings.NewReader(test.body))
		request.Header.Set("Authorization", test.authorization)
		request.Header.Set("Origin", test.requestOrigin)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("实时日志管理接口状态错误: %s %d", test.method, response.Code)
		}
		if test.status == 200 {
			var snapshot gateway.RequestLogSnapshot
			if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil || snapshot.Enabled != test.enabled || snapshot.Capacity != 500 || snapshot.Items == nil {
				t.Fatalf("采集状态错误: %+v %v", snapshot, err)
			}
		}
	}
}

func TestManagementSettingsNeverExposeCredentials(t *testing.T) {
	const origin = "http://127.0.0.1:38123"
	controller := &desktopController{values: settings.Values{Listen: "127.0.0.1:8080"}, token: "local-private-token", key: "upstream-private-key"}
	handler := controller.managementHandler(origin, "session")
	request := httptest.NewRequest(http.MethodGet, origin+"/api/settings", nil)
	request.Header.Set("Authorization", "Bearer session")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatal(response.Code)
	}
	if strings.Contains(response.Body.String(), controller.key) || strings.Contains(response.Body.String(), controller.token) {
		t.Fatal("设置接口泄露凭证")
	}
	if !strings.Contains(response.Body.String(), `"key_configured":true`) {
		t.Fatal("设置接口未返回密钥配置状态")
	}
}
