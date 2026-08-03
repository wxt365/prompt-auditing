//go:build !windows

package platform

import (
	"os"
	"syscall"
)

func ShutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}
