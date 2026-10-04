package proxy

import (
	"net"
	"strconv"
	"time"
)

// DefaultKeepAlive finds a silently dead peer in about 30s: 15s idle, then 3 probes 5s apart.
var DefaultKeepAlive = net.KeepAliveConfig{Enable: true, Idle: 15 * time.Second, Interval: 5 * time.Second, Count: 3}

// setKeepAlive applies an enabled cfg to a TCP conn; on Linux, unacknowledged writes give up after the same time.
func setKeepAlive(conn net.Conn, cfg net.KeepAliveConfig) error {
	tc, ok := conn.(*net.TCPConn)
	if !ok || !cfg.Enable {
		return nil
	}
	if err := tc.SetKeepAliveConfig(cfg); err != nil {
		return err
	}
	return setUserTimeout(tc, deadPeerTimeout(cfg))
}

// deadPeerTimeout is how long cfg takes to give up on a peer that stopped answering.
func deadPeerTimeout(cfg net.KeepAliveConfig) time.Duration {
	return cfg.Idle + cfg.Interval*time.Duration(cfg.Count)
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
		"tcp_user_timeout":        strconv.FormatInt(deadPeerTimeout(cfg).Milliseconds(), 10),
	}
}
