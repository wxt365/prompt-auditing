package gateway

import (
	"context"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsSocketConnectionRefusal(t *testing.T) {
	err := &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connectex", Err: windows.WSAECONNREFUSED}}
	if got := ClassifyUpstreamError(context.Background(), err, false); got != "upstream_connection_refused" {
		t.Fatalf("Windows 套接字错误分类错误: %s", got)
	}
}
