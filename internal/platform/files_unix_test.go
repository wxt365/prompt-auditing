//go:build !windows

package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecureDirRejectsExistingBroadDirectoryWithoutChangingPermissions(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SecureDir(directory); err == nil {
		t.Fatal("期望拒绝权限过宽的已存在目录")
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("已存在目录权限被修改为 %o", info.Mode().Perm())
	}
}

func TestSecureDirCreatesOwnerOnlyDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "new", "data")
	if err := SecureDir(directory); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSecureDir(directory); err != nil {
		t.Fatal(err)
	}
}
