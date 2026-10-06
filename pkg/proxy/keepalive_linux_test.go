package proxy

import "syscall"

const (
	keepIdleOpt    = syscall.TCP_KEEPIDLE
	userTimeoutOpt = 0x12 // TCP_USER_TIMEOUT, which package syscall lacks on amd64, 386 and arm
)
