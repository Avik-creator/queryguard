//go:build unix

package proxy

import (
	"runtime"
	"syscall"
)

// setReusePort lets several processes listen on one port, which Linux balances new connections across.
func setReusePort(fd uintptr) error {
	// SO_REUSEPORT is 15 on Linux, where package syscall lacks it on amd64, and 0x200 on macOS and the BSDs.
	opt := 0x200
	if runtime.GOOS == "linux" {
		opt = 0xf
	}
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, opt, 1)
}
