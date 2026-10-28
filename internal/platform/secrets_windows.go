//go:build windows

package platform

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

type secretBlob struct {
	Size uint32
	Data *byte
}

// Windows DPAPI 将密钥绑定到当前用户，不把明文凭证写入数据库。
func ProtectSecret(value []byte) ([]byte, error) {
	return transformSecret("CryptProtectData", value)
}

func UnprotectSecret(value []byte) ([]byte, error) {
	return transformSecret("CryptUnprotectData", value)
}

func transformSecret(name string, value []byte) ([]byte, error) {
	if len(value) == 0 {
		return nil, nil
	}
	in := secretBlob{Size: uint32(len(value)), Data: &value[0]}
	var out secretBlob
	procedure := windows.NewLazySystemDLL("crypt32.dll").NewProc(name)
	result, _, callErr := procedure.Call(uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 1, uintptr(unsafe.Pointer(&out)))
	if result == 0 {
		return nil, fmt.Errorf("Windows 密钥保护失败: %w", callErr)
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	return append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...), nil
}
