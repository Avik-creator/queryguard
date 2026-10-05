//go:build !unix

package proxy

import "errors"

// setReusePort fails: SO_REUSEPORT is a Unix socket option.
func setReusePort(uintptr) error { return errors.New("-reuse-port needs Linux, macOS or a BSD") }
