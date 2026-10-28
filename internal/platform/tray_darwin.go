//go:build darwin && cgo

package platform

/*
#cgo LDFLAGS: -framework AppKit -framework Security
#include <stdlib.h>
#include "desktop_darwin.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func init() {
	// AppKit 的事件循环必须运行在进程主线程。
	runtime.LockOSThread()
}

var darwinOpenConfig func()

//export gatewayOpenConfig
func gatewayOpenConfig() {
	if darwinOpenConfig != nil {
		darwinOpenConfig()
	}
}

func OpenBrowser(address string) error {
	if err := exec.Command("/usr/bin/open", address).Run(); err != nil {
		return fmt.Errorf("打开配置页面失败: %w", err)
	}
	return nil
}

func ShowDesktopError(message string) {
	text := C.CString(message)
	defer C.free(unsafe.Pointer(text))
	C.gateway_desktop_error(text)
}

func RunTray(open func(), showInitially bool) error {
	darwinOpenConfig = open
	defer func() { darwinOpenConfig = nil }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-signals:
			C.gateway_tray_stop()
		case <-done:
		}
	}()
	var initial C.int
	if showInitially {
		initial = 1
	}
	if C.gateway_tray_run(initial) != 0 {
		return errors.New("无法在 macOS 主线程创建菜单栏图标")
	}
	return nil
}

func LockDesktop() (func(), error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	return lockDesktopDirectory(filepath.Join(base, "CodexSecurityGateway"))
}

func lockDesktopDirectory(directory string) (func(), error) {
	if err := SecureDir(directory); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, "desktop.lock")
	descriptor, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("打开桌面实例锁: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), path)
	if err := ValidateSecureFile(path); err != nil {
		file.Close()
		return nil, err
	}
	if err := unix.Flock(descriptor, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("安全网关已在运行，请从顶部菜单栏打开管理界面")
		}
		return nil, fmt.Errorf("锁定桌面实例: %w", err)
	}
	// 保留锁文件，避免删除后其他实例锁定不同 inode。
	return func() { _ = file.Close() }, nil
}
