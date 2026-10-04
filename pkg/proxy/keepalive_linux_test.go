package proxy

import "syscall"

const (
	keepIdleOpt    = syscall.TCP_KEEPIDLE
	userTimeoutOpt = syscall.TCP_USER_TIMEOUT
)
