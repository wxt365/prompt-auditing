//go:build darwin && cgo

package platform

/*
#include <stdlib.h>
#include "desktop_darwin.h"
*/
import "C"

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"unsafe"
)

var keychainService = "com.prompt-auditing.gateway.settings"

const secretEnvelope = "CGKM1"

// 钥匙串保存加密密钥，设置库仅保存带随机 nonce 的认证密文。
func ProtectSecret(value []byte) ([]byte, error) {
	if len(value) == 0 {
		return nil, nil
	}
	aead, err := desktopSecretCipher(true)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	result := append([]byte(secretEnvelope), nonce...)
	return aead.Seal(result, nonce, value, []byte(secretEnvelope)), nil
}

func UnprotectSecret(value []byte) ([]byte, error) {
	if len(value) == 0 {
		return nil, nil
	}
	if !bytes.HasPrefix(value, []byte(secretEnvelope)) {
		return nil, errors.New("macOS 设置凭证格式无效，不能读取其他平台的加密设置")
	}
	aead, err := desktopSecretCipher(false)
	if err != nil {
		return nil, err
	}
	value = value[len(secretEnvelope):]
	if len(value) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("macOS 设置凭证不完整")
	}
	plain, err := aead.Open(nil, value[:aead.NonceSize()], value[aead.NonceSize():], []byte(secretEnvelope))
	if err != nil {
		return nil, errors.New("macOS 设置凭证校验失败")
	}
	return plain, nil
}

func desktopSecretCipher(create bool) (cipher.AEAD, error) {
	service := C.CString(keychainService)
	defer C.free(unsafe.Pointer(service))
	key := make([]byte, 32)
	defer clear(key)
	var allowCreate C.int
	if create {
		allowCreate = 1
	}
	status := C.gateway_keychain_key(service, allowCreate, (*C.uchar)(unsafe.Pointer(&key[0])))
	if status != 0 {
		return nil, fmt.Errorf("无法访问 macOS 钥匙串（状态 %d），请解锁登录钥匙串并允许安全网关访问；程序不会使用明文保存凭证", int(status))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
