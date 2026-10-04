//go:build !linux

package proxy

import (
	"net"
	"time"
)

// setUserTimeout does nothing: TCP_USER_TIMEOUT is Linux only.
func setUserTimeout(*net.TCPConn, time.Duration) error { return nil }
