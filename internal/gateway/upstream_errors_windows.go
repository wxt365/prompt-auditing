package gateway

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

func isConnectionRefused(err error) bool {
	// Windows 套接字错误与 syscall 的兼容错误码并不相同。
	return errors.Is(err, windows.WSAECONNREFUSED) || errors.Is(err, syscall.ECONNREFUSED)
}
