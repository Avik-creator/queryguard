package proxy

import "syscall"

const (
	keepIdleOpt    = syscall.TCP_KEEPIDLE
	userTimeoutOpt = tcpUserTimeout
)
