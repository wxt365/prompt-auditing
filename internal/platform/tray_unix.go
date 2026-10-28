//go:build !windows && (!darwin || !cgo)

package platform

import "errors"

func OpenBrowser(string) error     { return errors.New("桌面入口需要 Windows 或启用 CGO 的 macOS 构建") }
func ShowDesktopError(string)      {}
func RunTray(func(), bool) error   { return errors.New("托盘模式需要 Windows 或启用 CGO 的 macOS 构建") }
func LockDesktop() (func(), error) { return nil, errors.New("桌面入口需要 Windows 或启用 CGO 的 macOS 构建") }
