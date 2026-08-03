//go:build windows

package platform

import "os"

func ShutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}
