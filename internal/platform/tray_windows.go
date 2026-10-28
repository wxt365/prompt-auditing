//go:build windows

package platform

import (
	_ "embed"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	trayUser32  = windows.NewLazySystemDLL("user32.dll")
	trayShell32 = windows.NewLazySystemDLL("shell32.dll")
)

//go:embed gateway-tray.png
var trayIconPNG []byte

func loadTrayIcon() (uintptr, error) {
	icon, _, err := trayUser32.NewProc("CreateIconFromResourceEx").Call(
		uintptr(unsafe.Pointer(&trayIconPNG[0])), uintptr(len(trayIconPNG)), 1, 0x00030000, 32, 32, 0)
	if icon == 0 {
		return 0, fmt.Errorf("加载托盘图标失败: %v", err)
	}
	return icon, nil
}

type trayPoint struct{ X, Y int32 }
type trayMessage struct {
	Window         uintptr
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	Point          trayPoint
	Private        uint32
}
type trayWindowClass struct {
	Size, Style                        uint32
	Procedure                          uintptr
	ClassExtra, WindowExtra            int32
	Instance, Icon, Cursor, Background uintptr
	MenuName, ClassName                *uint16
	SmallIcon                          uintptr
}
type trayIconData struct {
	Size                uint32
	Window              uintptr
	ID, Flags, Callback uint32
	Icon                uintptr
	Tip                 [128]uint16
	State, StateMask    uint32
	Info                [256]uint16
	Version             uint32
	InfoTitle           [64]uint16
	InfoFlags           uint32
	GUID                [16]byte
	BalloonIcon         uintptr
}

func trayText(value string) *uint16 { result, _ := windows.UTF16PtrFromString(value); return result }

func OpenBrowser(url string) error {
	result, _, err := trayShell32.NewProc("ShellExecuteW").Call(0,
		uintptr(unsafe.Pointer(trayText("open"))), uintptr(unsafe.Pointer(trayText(url))), 0, 0, 1)
	if result <= 32 {
		return fmt.Errorf("打开配置页面失败: %v", err)
	}
	return nil
}

func ShowDesktopError(message string) {
	trayUser32.NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(trayText(message))),
		uintptr(unsafe.Pointer(trayText("Codex 安全网关"))), 0x10)
}

// 独立 GUI 入口没有控制台窗口，后台仅保留通知区域图标。
func RunTray(open func(), showInitially bool) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	instance, _, err := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetModuleHandleW").Call(0)
	if instance == 0 {
		return fmt.Errorf("读取程序模块失败: %v", err)
	}
	const trayEvent = 0x8001
	createdMessage, _, _ := trayUser32.NewProc("RegisterWindowMessageW").Call(uintptr(unsafe.Pointer(trayText("TaskbarCreated"))))
	var icon trayIconData
	var trayErr error
	notify := trayShell32.NewProc("Shell_NotifyIconW")
	addIcon := func() {
		if result, _, err := notify.Call(0, uintptr(unsafe.Pointer(&icon))); result == 0 {
			trayErr = fmt.Errorf("创建 Windows 托盘图标失败: %v", err)
		}
	}
	callback := syscall.NewCallback(func(window uintptr, message uint32, wparam, lparam uintptr) uintptr {
		if createdMessage != 0 && message == uint32(createdMessage) {
			addIcon()
			return 0
		}
		switch message {
		case trayEvent:
			switch uint32(lparam) {
			case 0x0202:
				open()
			case 0x0205, 0x007b:
				menu, _, _ := trayUser32.NewProc("CreatePopupMenu").Call()
				if menu == 0 {
					return 0
				}
				defer trayUser32.NewProc("DestroyMenu").Call(menu)
				trayUser32.NewProc("AppendMenuW").Call(menu, 0, 1, uintptr(unsafe.Pointer(trayText("打开配置界面"))))
				trayUser32.NewProc("AppendMenuW").Call(menu, 0x800, 0, 0)
				trayUser32.NewProc("AppendMenuW").Call(menu, 0, 2, uintptr(unsafe.Pointer(trayText("退出"))))
				var point trayPoint
				trayUser32.NewProc("GetCursorPos").Call(uintptr(unsafe.Pointer(&point)))
				trayUser32.NewProc("SetForegroundWindow").Call(window)
				command, _, _ := trayUser32.NewProc("TrackPopupMenu").Call(menu, 0x182,
					uintptr(point.X), uintptr(point.Y), 0, window, 0)
				if command == 1 {
					open()
				}
				if command == 2 {
					trayUser32.NewProc("PostMessageW").Call(window, 0x0010, 0, 0)
				}
				trayUser32.NewProc("PostMessageW").Call(window, 0, 0, 0)
			}
			return 0
		case 0x0010:
			trayUser32.NewProc("PostQuitMessage").Call(0)
			return 0
		}
		result, _, _ := trayUser32.NewProc("DefWindowProcW").Call(window, uintptr(message), wparam, lparam)
		return result
	})
	className := trayText("CodexSecurityGatewayTray")
	class := trayWindowClass{Size: uint32(unsafe.Sizeof(trayWindowClass{})), Procedure: callback, Instance: uintptr(instance), ClassName: className}
	atom, _, err := trayUser32.NewProc("RegisterClassExW").Call(uintptr(unsafe.Pointer(&class)))
	if atom == 0 {
		return fmt.Errorf("注册托盘窗口失败: %v", err)
	}
	defer trayUser32.NewProc("UnregisterClassW").Call(uintptr(unsafe.Pointer(className)), uintptr(instance))
	window, _, err := trayUser32.NewProc("CreateWindowExW").Call(0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(className)), 0, 0, 0, 0, 0, 0, 0, uintptr(instance), 0)
	if window == 0 {
		return fmt.Errorf("创建托盘窗口失败: %v", err)
	}
	defer trayUser32.NewProc("DestroyWindow").Call(window)
	shield, err := loadTrayIcon()
	if err != nil {
		return err
	}
	defer trayUser32.NewProc("DestroyIcon").Call(shield)
	icon = trayIconData{Size: uint32(unsafe.Sizeof(trayIconData{})), Window: window, ID: 1, Flags: 7, Callback: trayEvent, Icon: shield}
	tip, _ := windows.UTF16FromString("Codex 安全网关 · 单击打开配置")
	copy(icon.Tip[:], tip)
	addIcon()
	if trayErr != nil {
		return trayErr
	}
	defer notify.Call(2, uintptr(unsafe.Pointer(&icon)))
	if showInitially {
		open()
	}
	var message trayMessage
	for {
		result, _, callErr := trayUser32.NewProc("GetMessageW").Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		if int32(result) == -1 {
			return fmt.Errorf("托盘消息循环失败: %v", callErr)
		}
		if result == 0 {
			return trayErr
		}
		trayUser32.NewProc("TranslateMessage").Call(uintptr(unsafe.Pointer(&message)))
		trayUser32.NewProc("DispatchMessageW").Call(uintptr(unsafe.Pointer(&message)))
	}
}

func LockDesktop() (func(), error) {
	sid, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateMutex(nil, false, trayText("Local\\CodexSecurityGateway-"+sid.String()))
	if handle != 0 && err != nil {
		windows.CloseHandle(handle)
	}
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil, errors.New("安全网关已在运行，请从右下角托盘打开配置界面")
	}
	if err != nil {
		return nil, err
	}
	return func() { windows.CloseHandle(handle) }, nil
}
