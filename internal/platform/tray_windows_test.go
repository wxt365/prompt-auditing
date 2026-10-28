//go:build windows && native_e2e

package platform

import (
	"testing"
	"time"
	"unsafe"
)

func TestNativeTrayHiddenWindowOpenAndExit(t *testing.T) {
	opened := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() { done <- RunTray(func() { opened <- struct{}{} }, false) }()
	var window uintptr
	deadline := time.Now().Add(10 * time.Second)
	for window == 0 && time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("托盘提前退出: %v", err)
		default:
		}
		window, _, _ = trayUser32.NewProc("FindWindowW").Call(uintptr(unsafe.Pointer(trayText("CodexSecurityGatewayTray"))), 0)
		if window == 0 {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if window == 0 {
		t.Fatal("未创建托盘消息窗口")
	}
	defer trayUser32.NewProc("PostMessageW").Call(window, 0x0010, 0, 0)
	if visible, _, _ := trayUser32.NewProc("IsWindowVisible").Call(window); visible != 0 {
		t.Fatal("托盘窗口不应可见")
	}
	// 发送通知区域的单击回调，验证窗口过程可以正确调用 Go 函数。
	trayUser32.NewProc("PostMessageW").Call(window, 0x8001, 1, 0x0202)
	select {
	case <-opened:
	case <-time.After(5 * time.Second):
		t.Fatal("托盘单击未触发打开配置")
	}
	trayUser32.NewProc("PostMessageW").Call(window, 0x0010, 0, 0)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("托盘未退出")
	}
}
