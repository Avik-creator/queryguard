package proxy

import "syscall"

const (
	keepIdleOpt = syscall.TCP_KEEPALIVE
	// macOS has no TCP_USER_TIMEOUT.
	userTimeoutOpt = 0
)
