//go:build !windows

package platform

import (
	"errors"
	"fmt"
	"os"
)

func SecureDir(path string) error {
	info, err := os.Stat(path)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("路径不是目录: %s", path)
		}
		return ValidateSecureDir(path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	return ValidateSecureDir(path)
}

func SecureFile(path string) error {
	return os.Chmod(path, 0o600)
}

func ValidateSecureDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("路径不是目录: %s", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("目录权限过宽: %s", path)
	}
	return nil
}

func ValidateSecureFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("路径不是普通文件: %s", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("文件权限过宽: %s", path)
	}
	return nil
}

func ValidateTrustedDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("路径不是目录: %s", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("目录可被其他用户写入: %s", path)
	}
	return nil
}
