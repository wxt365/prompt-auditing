//go:build darwin && cgo && native_e2e

package platform

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if os.Getenv("GATEWAY_DARWIN_TRAY_HELPER") == "1" {
		if err := RunTray(func() { fmt.Println("native-menu-ready") }, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if service := os.Getenv("GATEWAY_DARWIN_KEY_HELPER"); service != "" {
		keychainService = service
		sealed, err := hex.DecodeString(os.Getenv("GATEWAY_DARWIN_SEALED"))
		if err == nil {
			var value []byte
			value, err = UnprotectSecret(sealed)
			if string(value) != "native-test-credential" {
				err = fmt.Errorf("子进程没有恢复预期凭证")
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestNativeDarwinMenuStartsAndStops(t *testing.T) {
	process := exec.Command(os.Args[0])
	process.Env = append(os.Environ(), "GATEWAY_DARWIN_TRAY_HELPER=1")
	stdout, err := process.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var diagnostics bytes.Buffer
	process.Stderr = &diagnostics
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Process.Kill() })
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == "native-menu-ready" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("菜单栏未完成启动")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("等待菜单栏启动超时")
	}
	if err := process.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("菜单栏未正常退出: %v %s", err, diagnostics.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("菜单栏退出超时")
	}
}

func TestNativeDarwinKeychainEncryptsAndRestoresAcrossProcesses(t *testing.T) {
	previous := keychainService
	keychainService = fmt.Sprintf("com.prompt-auditing.gateway.test.%d.%d", os.Getpid(), time.Now().UnixNano())
	defer func() { keychainService = previous }()
	defer func() {
		// 只删除本测试创建的独立钥匙串条目，不访问用户已有的网关密钥。
		if output, err := exec.Command("/usr/bin/security", "delete-generic-password", "-s", keychainService, "-a", "desktop-settings-key-v1").CombinedOutput(); err != nil {
			t.Errorf("清理测试钥匙串条目失败: %v %s", err, output)
		}
	}()
	if _, err := desktopSecretCipher(false); err == nil {
		t.Fatal("缺失解密密钥时不应自动新建密钥")
	}
	const plain = "native-test-credential"
	sealed, err := ProtectSecret([]byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(plain)) {
		t.Fatal("设置密文包含明文凭证")
	}
	second, err := ProtectSecret([]byte(plain))
	if err != nil || bytes.Equal(sealed, second) {
		t.Fatal("相同凭证必须使用不同随机 nonce")
	}
	process := exec.Command(os.Args[0])
	process.Env = append(os.Environ(), "GATEWAY_DARWIN_KEY_HELPER="+keychainService, "GATEWAY_DARWIN_SEALED="+hex.EncodeToString(sealed))
	if output, err := process.CombinedOutput(); err != nil {
		t.Fatalf("子进程恢复凭证失败: %v %s", err, output)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := UnprotectSecret(sealed); err == nil {
		t.Fatal("被篡改的设置凭证不应通过认证")
	}
	for _, invalid := range [][]byte{[]byte("windows-blob"), []byte(secretEnvelope), sealed[:len(secretEnvelope)+1]} {
		if _, err := UnprotectSecret(invalid); err == nil {
			t.Fatal("无效密文不应被读取")
		}
	}
	if value, err := UnprotectSecret(nil); err != nil || len(value) != 0 {
		t.Fatal("空凭证不应访问钥匙串")
	}
}
