package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"
)

func TestRelaysBytesBothWays(t *testing.T) {
	addr, _ := startProxy(t, newServer(t, startEcho(t)))
	conn := dial(t, addr)

	roundTrip(t, conn, "hello")
}

func TestClosesClientWhenUpstreamUnreachable(t *testing.T) {
	// A port that was just released has nothing listening on it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := ln.Addr().String()
	ln.Close()

	addr, _ := startProxy(t, newServer(t, upstream))
	conn := dial(t, addr)

	expectClosed(t, conn)
}

func TestClosesClientWhenUpstreamCloses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	addr, _ := startProxy(t, newServer(t, ln.Addr().String()))
	conn := dial(t, addr)

	expectClosed(t, conn)
}

func TestServeReturnsNilWhenStopped(t *testing.T) {
	_, stop := startProxy(t, newServer(t, startEcho(t)))

	if err := stop(); err != nil {
		t.Fatalf("Serve returned %v; want nil", err)
	}
}

func TestShutdownWaitsForOpenSessions(t *testing.T) {
	s := newServer(t, startEcho(t))
	s.ShutdownTimeout = 5 * time.Second
	addr, stop := startProxy(t, s)
	conn := dial(t, addr)
	roundTrip(t, conn, "before")

	done := make(chan error, 1)
	go func() { done <- stop() }()

	select {
	case <-done:
		t.Fatal("Serve returned while a session was still open")
	case <-time.After(200 * time.Millisecond):
	}
	if c, err := net.Dial("tcp", addr); err == nil {
		c.Close()
		t.Error("proxy accepted a new connection during shutdown")
	}
	roundTrip(t, conn, "during")

	conn.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v; want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after the last session ended")
	}
}

func TestShutdownClosesSessionsAfterTimeout(t *testing.T) {
	s := newServer(t, startEcho(t))
	s.ShutdownTimeout = 100 * time.Millisecond
	addr, stop := startProxy(t, s)
	conn := dial(t, addr)
	roundTrip(t, conn, "hello")

	start := time.Now()
	if err := stop(); err != nil {
		t.Fatalf("Serve returned %v; want nil", err)
	}
	if elapsed := time.Since(start); elapsed < s.ShutdownTimeout {
		t.Errorf("Serve returned after %v; want at least the %v timeout", elapsed, s.ShutdownTimeout)
	}
	expectClosed(t, conn)
}

// newServer returns a Server for upstream that logs to the test output.
func newServer(t *testing.T, upstream string) *Server {
	return &Server{
		Upstream: upstream,
		Logger:   slog.New(slog.NewTextHandler(t.Output(), nil)),
	}
}

// startEcho starts a TCP server that writes back what it reads, standing in for Postgres.
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// startProxy runs s.Serve on a free port and returns its address and a stop function.
func startProxy(t *testing.T, s *Server) (addr string, stop func() error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- s.Serve(ctx, ln) }()

	stopped := false
	stop = func() error {
		cancel()
		stopped = true
		return <-errc
	}
	t.Cleanup(func() {
		if !stopped {
			stop()
		}
	})
	return ln.Addr().String(), stop
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// roundTrip sends msg through conn and checks the echo comes back.
func roundTrip(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	defer conn.SetDeadline(time.Time{})
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != msg {
		t.Fatalf("got %q back; want %q", got, msg)
	}
}

// expectClosed fails the test unless the proxy closes conn within 2s.
func expectClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := conn.Read(make([]byte, 1))
	switch {
	case err == nil:
		t.Fatal("read succeeded; want the proxy to close the connection")
	case errors.Is(err, os.ErrDeadlineExceeded):
		t.Fatal("connection still open after 2s; want the proxy to close it")
	}
}
