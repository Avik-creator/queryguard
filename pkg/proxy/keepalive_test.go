//go:build linux || darwin

package proxy

import (
	"net"
	"syscall"
	"testing"
	"time"
)

// testKeepAlive differs from DefaultKeepAlive so the tests can't pass on defaults.
var testKeepAlive = net.KeepAliveConfig{Enable: true, Idle: 7 * time.Second, Interval: 3 * time.Second, Count: 4}

func TestSetsKeepAliveOnClientConnections(t *testing.T) {
	s := newServer(t, startFakePostgres(t).addr)
	s.KeepAlive = testKeepAlive
	ln := &recordingListener{Listener: listen(t), accepted: make(chan net.Conn, 1)}
	startProxyOn(t, s, ln)

	startSession(t, ln.Addr().String())

	expectKeepAlive(t, <-ln.accepted, testKeepAlive)
}

func TestSetsKeepAliveOnServerConnections(t *testing.T) {
	pg := startFakePostgres(t)

	conn, err := Dialer{Addr: pg.addr, KeepAlive: testKeepAlive}.dial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	expectKeepAlive(t, conn, testKeepAlive)
}

// recordingListener passes on every connection it accepts.
type recordingListener struct {
	net.Listener
	accepted chan net.Conn
}

func (l *recordingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.accepted <- conn
	}
	return conn, err
}

// expectKeepAlive reads conn's socket options and compares them with cfg.
func expectKeepAlive(t *testing.T, conn net.Conn, cfg net.KeepAliveConfig) {
	t.Helper()
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][3]int{
		"keepalive idle": {syscall.IPPROTO_TCP, keepIdleOpt, int(cfg.Idle / time.Second)},
		"TCP_KEEPINTVL":  {syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, int(cfg.Interval / time.Second)},
		"TCP_KEEPCNT":    {syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, cfg.Count},
	}
	if userTimeoutOpt != 0 {
		// The kernel's own retransmission limit is left alone, so a client whose window stays shut isn't cut off.
		want["TCP_USER_TIMEOUT"] = [3]int{syscall.IPPROTO_TCP, userTimeoutOpt, 0}
	}
	raw.Control(func(fd uintptr) {
		// macOS reports the option's flag value rather than 1.
		if on, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE); err != nil || on == 0 {
			t.Errorf("SO_KEEPALIVE = %d, %v; want on", on, err)
		}
		for name, opt := range want {
			got, err := syscall.GetsockoptInt(int(fd), opt[0], opt[1])
			if err != nil || got != opt[2] {
				t.Errorf("%s = %d, %v; want %d", name, got, err, opt[2])
			}
		}
	})
}
