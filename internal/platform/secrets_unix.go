//go:build !windows && (!darwin || !cgo)

package platform

import "errors"

func ProtectSecret([]byte) ([]byte, error) {
	return nil, errors.New("当前平台暂不支持界面保存密钥，请使用命令行和环境变量")
}

func UnprotectSecret([]byte) ([]byte, error) {
	return nil, errors.New("当前平台暂不支持读取 Windows 加密密钥")
}
