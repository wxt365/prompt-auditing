//go:build darwin && cgo

package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDarwinDesktopLockExcludesSecondInstanceAndReleases(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private-data")
	unlock, err := lockDesktopDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if release, err := lockDesktopDirectory(directory); err == nil {
		release()
		t.Fatal("第二个实例不应取得同一数据目录的锁")
	}
	unlock()
	release, err := lockDesktopDirectory(directory)
	if err != nil {
		t.Fatalf("退出后应释放实例锁: %v", err)
	}
	defer release()
	// 锁文件不能被删除，否则新实例可能锁定不同 inode。
	if _, err := os.Stat(filepath.Join(directory, "desktop.lock")); err != nil {
		t.Fatal(err)
	}
}

func TestDarwinDesktopLockRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, "desktop.lock")); err != nil {
		t.Fatal(err)
	}
	if release, err := lockDesktopDirectory(directory); err == nil {
		release()
		t.Fatal("不应跟随符号链接取得实例锁")
	}
}
