package proxy

import (
	"net"
	"strconv"
	"time"
)

// DefaultKeepAlive finds a silently dead peer in about 30s: 15s idle, then 3 probes 5s apart.
var DefaultKeepAlive = net.KeepAliveConfig{Enable: true, Idle: 15 * time.Second, Interval: 5 * time.Second, Count: 3}

// setKeepAlive applies an enabled cfg to a TCP conn. It sets no TCP_USER_TIMEOUT: since Linux 5.11 that also cuts off a live
// peer whose receive window stays shut that long, as a client that stops reading a large result does.
func setKeepAlive(conn net.Conn, cfg net.KeepAliveConfig) error {
	tc, ok := conn.(*net.TCPConn)
	if !ok || !cfg.Enable {
		return nil
	}
	return tc.SetKeepAliveConfig(cfg)
}

// keepAliveSettings are the Postgres settings that make its side of the connection follow cfg.
func keepAliveSettings(cfg net.KeepAliveConfig) map[string]string {
	if !cfg.Enable {
		return nil
	}
	return map[string]string{
		"tcp_keepalives_idle":     strconv.Itoa(int(cfg.Idle / time.Second)),
		"tcp_keepalives_interval": strconv.Itoa(int(cfg.Interval / time.Second)),
		"tcp_keepalives_count":    strconv.Itoa(cfg.Count),
	}
}
