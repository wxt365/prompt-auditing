//go:build !windows

package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitRejectsConfigInDirectoryWritableByOtherUsers(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "untrusted")
	if err := os.Mkdir(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	configPath := writeTestConfig(t, directory)
	_, stderr, code := runForTest([]string{"init", "--config", configPath})
	if code != 1 || !strings.Contains(stderr, "配置目录不可信") {
		t.Fatalf("不可信配置目录响应错误: code=%d stderr=%q", code, stderr)
	}
}
