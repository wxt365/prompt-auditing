//go:build windows

package platform

import "testing"

func TestBundledTrayIconLoadsInWindows(t *testing.T) {
	icon, err := loadTrayIcon()
	if err != nil {
		t.Fatal(err)
	}
	if result, _, err := trayUser32.NewProc("DestroyIcon").Call(icon); result == 0 {
		t.Fatalf("释放托盘图标失败: %v", err)
	}
}
