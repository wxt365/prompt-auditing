//go:build native_e2e && windows

package e2e_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/xiaotaowang/prompt-auditing/internal/settings"
	"github.com/xiaotaowang/prompt-auditing/internal/storage"
	"golang.org/x/sys/windows"
)

func TestWindowsDesktopArtifactRestoresSettingsAndExits(t *testing.T) {
	for _, mode := range []string{settings.AuthGateway, settings.AuthClient} {
		t.Run(mode, func(t *testing.T) { testWindowsDesktopArtifactAuthMode(t, mode) })
	}
}

func testWindowsDesktopArtifactAuthMode(t *testing.T, mode string) {
	binary := os.Getenv("GATEWAY_DESKTOP_BINARY")
	if binary == "" {
		t.Skip("设置 GATEWAY_DESKTOP_BINARY 后运行桌面产物验证")
	}
	user32 := windows.NewLazySystemDLL("user32.dll")
	class, _ := windows.UTF16PtrFromString("CodexSecurityGatewayTray")
	findWindow := func() uintptr {
		window, _, _ := user32.NewProc("FindWindowW").Call(uintptr(unsafe.Pointer(class)), 0)
		return window
	}
	if findWindow() != 0 {
		t.Skip("已有桌面网关运行，保留用户实例")
	}
	requests := make(chan string, 4)
	const sse = "data: {\"ok\":true}\n\ndata: [DONE]\n\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer desktop-artifact-key" || strings.Contains(string(body), "内部系统A") || !strings.Contains(string(body), "业务系统") {
			t.Error("桌面产物上游认证或脱敏错误")
		}
		requests <- r.URL.Path
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, sse)
	}))
	defer upstream.Close()
	appData := t.TempDir()
	directory := filepath.Join(appData, "CodexSecurityGateway")
	store, err := settings.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	values, token, _, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	values.Listen = fmt.Sprintf("127.0.0.1:%d", windowsAvailablePort(t))
	values.Upstream = upstream.URL + "/v1"
	values.AuthMode = mode
	values.SetupRequired = false
	if err := store.Save(context.Background(), values, token, "desktop-artifact-key"); err != nil {
		t.Fatal(err)
	}
	cfg, err := store.Config(values)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := storage.InitDatabases(context.Background(), cfg.PolicyDB, cfg.AuditDB); err != nil {
		t.Fatal(err)
	}
	policy, err := storage.OpenPolicy(context.Background(), cfg.PolicyDB)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.AddBlock(context.Background(), "customer", []string{"客户A"}, false); err != nil {
		t.Fatal(err)
	}
	if err := policy.AddReplacement(context.Background(), "system", []storage.Mapping{{Source: "内部系统A", Target: "业务系统"}}, false); err != nil {
		t.Fatal(err)
	}
	if err := policy.Close(); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	// 连续两次启动相同产物，验证凭证、规则恢复及退出时释放单实例锁。
	for iteration := 0; iteration < 2; iteration++ {
		process := exec.Command(binary)
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(strings.ToUpper(entry), "APPDATA=") {
				process.Env = append(process.Env, entry)
			}
		}
		process.Env = append(process.Env, "APPDATA="+appData)
		if err := process.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- process.Wait() }()
		t.Cleanup(func() { _ = process.Process.Kill() })
		var window uintptr
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case err := <-done:
				t.Fatalf("桌面产物提前退出: %v", err)
			default:
			}
			window = findWindow()
			if window != 0 {
				response, err := client.Get("http://" + values.Listen + "/healthz")
				if err == nil {
					response.Body.Close()
					if response.StatusCode == http.StatusOK {
						break
					}
				}
			}
			time.Sleep(25 * time.Millisecond)
		}
		if window == 0 {
			t.Fatal("桌面产物未创建托盘窗口")
		}
		var pid uint32
		user32.NewProc("GetWindowThreadProcessId").Call(window, uintptr(unsafe.Pointer(&pid)))
		if pid != uint32(process.Process.Pid) {
			t.Fatal("托盘窗口不属于测试进程")
		}
		if visible, _, _ := user32.NewProc("IsWindowVisible").Call(window); visible != 0 {
			t.Fatal("桌面产物存在可见窗口")
		}
		for _, path := range []string{"/v1/responses", "/v1/chat/completions"} {
			for _, blocked := range []bool{true, false} {
				text, want := "内部系统A", http.StatusOK
				if blocked {
					text, want = "客户A", http.StatusForbidden
				}
				body := fmt.Sprintf(`{"model":"test","stream":true,"input":%q}`, text)
				if path == "/v1/responses" {
					body = fmt.Sprintf(`{"model":"test","stream":true,"reasoning":{"effort":"high","context":"auto"},"input":[{"type":"additional_tools","id":"tools_1","role":"developer","tools":[{"type":"namespace","name":"functions","description":"normal","tools":[{"type":"function","name":"probe","parameters":{"type":"object","properties":{"image_url":{"type":"string"}}}}]}]},{"type":"message","role":"user","content":[{"type":"input_text","text":%q},{"type":"input_image","image_url":"data:image/png;base64,YmluYXJ5","detail":"original"}]},{"type":"custom_tool_call","call_id":"call_patch","namespace":"functions","name":"apply_patch","input":"normal"},{"type":"custom_tool_call_output","call_id":"call_patch","output":"normal"}]}`, text)
				}
				if strings.HasSuffix(path, "completions") {
					body = fmt.Sprintf(`{"model":"test","stream":true,"messages":[{"role":"user","content":%q}]}`, text)
				}
				r, _ := http.NewRequest(http.MethodPost, "http://"+values.Listen+path, strings.NewReader(body))
				credential := token
				if mode == settings.AuthClient {
					credential = "desktop-artifact-key"
				}
				r.Header.Set("Authorization", "Bearer "+credential)
				r.Header.Set("Content-Type", "application/json")
				response, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				result, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || response.StatusCode != want || (!blocked && string(result) != sse) {
					t.Fatalf("桌面代理错误: status=%d body=%s err=%v", response.StatusCode, result, err)
				}
				if blocked {
					if len(requests) != 0 {
						t.Fatal("阻断请求到达上游")
					}
				} else {
					select {
					case actual := <-requests:
						if actual != path {
							t.Fatalf("上游路径=%s", actual)
						}
					case <-time.After(time.Second):
						t.Fatal("上游未收到请求")
					}
				}
			}
		}
		user32.NewProc("PostMessageW").Call(window, 0x0010, 0, 0)
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("桌面产物未正常退出")
		}
	}
}
