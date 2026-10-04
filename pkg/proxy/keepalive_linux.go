package proxy

import (
	"net"
	"syscall"
	"time"
)

// setUserTimeout makes the kernel drop conn when sent data stays unacknowledged for d, which keepalive alone misses.
func setUserTimeout(conn *net.TCPConn, d time.Duration) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	if err := raw.Control(func(fd uintptr) {
		setErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_USER_TIMEOUT, int(d.Milliseconds()))
	}); err != nil {
		return err
	}
	return setErr
}
