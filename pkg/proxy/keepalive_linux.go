package proxy

import (
	"net"
	"syscall"
	"time"
)

// tcpUserTimeout is TCP_USER_TIMEOUT from linux/tcp.h, 18 on every architecture; package syscall lacks it on amd64, 386 and arm.
const tcpUserTimeout = 0x12

// setUserTimeout makes the kernel drop conn when sent data stays unacknowledged for d, which keepalive alone misses.
func setUserTimeout(conn *net.TCPConn, d time.Duration) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	if err := raw.Control(func(fd uintptr) {
		setErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeout, int(d.Milliseconds()))
	}); err != nil {
		return err
	}
	return setErr
}
