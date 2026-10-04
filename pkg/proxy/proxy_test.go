package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/Avik-creator/queryguard/internal/testcert"
	"github.com/Avik-creator/queryguard/pkg/wire"
	"github.com/jackc/pgx/v5/pgproto3"
)

func TestForwardsStartupToUpstream(t *testing.T) {
	pg := startFakePostgres(t)
	addr, _ := startProxy(t, newServer(t, pg.addr))

	startSession(t, addr)

	got := mustReceive[*pgproto3.StartupMessage](t, pg.received)
	if got.Parameters["user"] != "alice" || got.Parameters["database"] != "shop" {
		t.Errorf("upstream got %v; want user alice, database shop", got.Parameters)
	}
}

func TestRelaysBytesBothWays(t *testing.T) {
	pg := startFakePostgres(t)
	addr, _ := startProxy(t, newServer(t, pg.addr))
	conn := startSession(t, addr)

	roundTrip(t, conn, "hello")
}

func TestForwardsCancelRequest(t *testing.T) {
	pg := startFakePostgres(t)
	addr, _ := startProxy(t, newServer(t, pg.addr))
	conn := dial(t, addr)
	key := bytes.Repeat([]byte{9}, 32)

	send(t, conn, &pgproto3.CancelRequest{ProcessID: 42, SecretKey: key})

	got := mustReceive[*pgproto3.CancelRequest](t, pg.received)
	if got.ProcessID != 42 || !bytes.Equal(got.SecretKey, key) {
		t.Errorf("upstream got %+v; want process 42 and the same key", got)
	}
	expectClosed(t, conn)
}

func TestRelaysOverDirectTLS(t *testing.T) {
	cert, clientTLS := testcert.Pair(t)
	s := newServer(t, startFakePostgres(t).addr)
	s.TLSConfig = wire.ServerTLSConfig(cert)
	addr, _ := startProxy(t, s)

	clientTLS.NextProtos = []string{"postgresql"}
	conn := login(t, tls.Client(dial(t, addr), clientTLS))

	roundTrip(t, conn, "hello over TLS")
}

func TestForwardsCancelRequestOverTLS(t *testing.T) {
	cert, clientTLS := testcert.Pair(t)
	pg := startFakePostgres(t)
	s := newServer(t, pg.addr)
	s.TLSConfig = wire.ServerTLSConfig(cert)
	addr, _ := startProxy(t, s)

	raw := dial(t, addr)
	send(t, raw, &pgproto3.SSLRequest{})
	reply := make([]byte, 1)
	if _, err := io.ReadFull(raw, reply); err != nil || reply[0] != 'S' {
		t.Fatalf("got %q, %v; want 'S'", reply, err)
	}
	send(t, tls.Client(raw, clientTLS), &pgproto3.CancelRequest{ProcessID: 42, SecretKey: []byte{1, 2, 3, 4}})

	if got := mustReceive[*pgproto3.CancelRequest](t, pg.received); got.ProcessID != 42 {
		t.Errorf("upstream got process %d; want 42", got.ProcessID)
	}
}

func TestHidesChannelBindingFromClient(t *testing.T) {
	pg := serveFakePostgres(t, &fakePostgres{greeting: []encoder{
		&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"}},
	}})
	addr, _ := startProxy(t, newServer(t, pg.addr))
	conn := dial(t, addr)

	sendStartup(t, conn)

	sasl, ok := receive(t, conn).(*pgproto3.AuthenticationSASL)
	if !ok || !slices.Equal(sasl.AuthMechanisms, []string{"SCRAM-SHA-256"}) {
		t.Fatalf("client got %#v; want SASL with only SCRAM-SHA-256", sasl)
	}
}

func TestStaysQuietWhenClientLeavesDuringLogin(t *testing.T) {
	pg := serveFakePostgres(t, &fakePostgres{greeting: []encoder{
		&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}},
	}})
	var logs bytes.Buffer
	s := newServer(t, pg.addr)
	s.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	addr, stop := startProxy(t, s)
	conn := dial(t, addr)
	sendStartup(t, conn)
	receive(t, conn)

	conn.Close()
	stop()

	if logs.Len() > 0 {
		t.Errorf("proxy logged %q; want nothing", logs.String())
	}
}

func TestConnectsToUpstreamOverTLS(t *testing.T) {
	cert, clientTLS := testcert.Pair(t)
	pg := serveFakePostgres(t, &fakePostgres{tls: wire.ServerTLSConfig(cert)})
	s := newServer(t, pg.addr)
	s.Upstream = Dialer{Addr: pg.addr, TLSConfig: clientTLS}
	addr, _ := startProxy(t, s)

	conn := startSession(t, addr)

	roundTrip(t, conn, "hello")
}

func TestForwardsCancelRequestToUpstreamOverTLS(t *testing.T) {
	cert, clientTLS := testcert.Pair(t)
	pg := serveFakePostgres(t, &fakePostgres{tls: wire.ServerTLSConfig(cert)})
	s := newServer(t, pg.addr)
	s.Upstream = Dialer{Addr: pg.addr, TLSConfig: clientTLS}
	addr, _ := startProxy(t, s)

	send(t, dial(t, addr), &pgproto3.CancelRequest{ProcessID: 42, SecretKey: []byte{1, 2, 3, 4}})

	if got := mustReceive[*pgproto3.CancelRequest](t, pg.received); got.ProcessID != 42 {
		t.Errorf("upstream got process %d; want 42", got.ProcessID)
	}
}

func TestFailsWhenUpstreamRefusesTLS(t *testing.T) {
	_, clientTLS := testcert.Pair(t)
	pg := startFakePostgres(t)
	s := newServer(t, pg.addr)
	s.Upstream = Dialer{Addr: pg.addr, TLSConfig: clientTLS}
	addr, _ := startProxy(t, s)
	conn := dial(t, addr)

	sendStartup(t, conn)

	expectFatal(t, conn, "08006")
}

func TestFailsWhenUpstreamCertificateIsUntrusted(t *testing.T) {
	cert, _ := testcert.Pair(t)
	pg := serveFakePostgres(t, &fakePostgres{tls: wire.ServerTLSConfig(cert)})
	s := newServer(t, pg.addr)
	s.Upstream = Dialer{Addr: pg.addr, TLSConfig: &tls.Config{ServerName: "localhost"}}
	addr, _ := startProxy(t, s)
	conn := dial(t, addr)

	sendStartup(t, conn)

	expectFatal(t, conn, "08006")
}

func TestSendsFatalErrorWhenUpstreamUnreachable(t *testing.T) {
	// A port that was just released has nothing listening on it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := ln.Addr().String()
	ln.Close()

	addr, _ := startProxy(t, newServer(t, upstream))
	conn := dial(t, addr)
	sendStartup(t, conn)

	expectFatal(t, conn, "08006")
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
	sendStartup(t, conn)

	expectClosed(t, conn)
}

func TestClosesClientThatSendsNoStartup(t *testing.T) {
	s := newServer(t, startFakePostgres(t).addr)
	s.StartupTimeout = 100 * time.Millisecond
	addr, _ := startProxy(t, s)

	conn := dial(t, addr)

	expectClosed(t, conn)
}

func TestServeReturnsNilWhenStopped(t *testing.T) {
	_, stop := startProxy(t, newServer(t, startFakePostgres(t).addr))

	if err := stop(); err != nil {
		t.Fatalf("Serve returned %v; want nil", err)
	}
}

func TestShutdownWaitsForOpenSessions(t *testing.T) {
	s := newServer(t, startFakePostgres(t).addr)
	s.ShutdownTimeout = 5 * time.Second
	addr, stop := startProxy(t, s)
	conn := startSession(t, addr)
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
	s := newServer(t, startFakePostgres(t).addr)
	s.ShutdownTimeout = 100 * time.Millisecond
	addr, stop := startProxy(t, s)
	conn := startSession(t, addr)
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
		Upstream: Dialer{Addr: upstream},
		Logger:   slog.New(slog.NewTextHandler(t.Output(), nil)),
	}
}

// fakePostgres records each client's startup packet, sends its greeting, then echoes bytes back.
type fakePostgres struct {
	addr     string
	received chan pgproto3.FrontendMessage
	tls      *tls.Config // when set, plaintext connections are dropped
	greeting []encoder   // sent after a startup message; AuthenticationOk when empty
}

func startFakePostgres(t *testing.T) *fakePostgres { return serveFakePostgres(t, &fakePostgres{}) }

func serveFakePostgres(t *testing.T, pg *fakePostgres) *fakePostgres {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	pg.addr = ln.Addr().String()
	pg.received = make(chan pgproto3.FrontendMessage, 10)
	greeting := pg.greeting
	if len(greeting) == 0 {
		greeting = []encoder{&pgproto3.AuthenticationOk{}}
	}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				conn, msg, err := wire.Negotiate(raw, pg.tls)
				if err != nil {
					return
				}
				if _, ok := conn.(*tls.Conn); pg.tls != nil && !ok {
					return
				}
				pg.received <- msg
				if _, ok := msg.(*pgproto3.StartupMessage); !ok {
					return
				}
				for _, m := range greeting {
					buf, _ := m.Encode(nil)
					conn.Write(buf)
				}
				io.Copy(conn, conn)
			}()
		}
	}()
	return pg
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

// startSession connects to the proxy and logs in.
func startSession(t *testing.T, addr string) net.Conn {
	t.Helper()
	return login(t, dial(t, addr))
}

// login sends a startup message on conn and waits for AuthenticationOk.
func login(t *testing.T, conn net.Conn) net.Conn {
	t.Helper()
	sendStartup(t, conn)
	if msg, ok := receive(t, conn).(*pgproto3.AuthenticationOk); !ok {
		t.Fatalf("got %#v; want AuthenticationOk", msg)
	}
	return conn
}

// sendStartup sends a startup message for alice and the shop database.
func sendStartup(t *testing.T, conn net.Conn) {
	t.Helper()
	send(t, conn, &pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersion30,
		Parameters:      map[string]string{"user": "alice", "database": "shop"},
	})
}

type encoder interface{ Encode([]byte) ([]byte, error) }

func send(t *testing.T, conn net.Conn, msg encoder) {
	t.Helper()
	buf, err := msg.Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(buf); err != nil {
		t.Fatal(err)
	}
}

// receive reads exactly one server message from conn within 2s.
func receive(t *testing.T, conn net.Conn) pgproto3.BackendMessage {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	head := make([]byte, 5)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatalf("read message: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint32(head[1:])-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read message: %v", err)
	}
	msg, err := pgproto3.NewFrontend(bytes.NewReader(append(head, body...)), io.Discard).Receive()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// expectFatal fails the test unless conn gets a FATAL error with code and is then closed.
func expectFatal(t *testing.T, conn net.Conn, code string) {
	t.Helper()
	msg := receive(t, conn)
	if e, ok := msg.(*pgproto3.ErrorResponse); !ok || e.Severity != "FATAL" || e.Code != code {
		t.Fatalf("got %#v; want FATAL %s", msg, code)
	}
	expectClosed(t, conn)
}

// mustReceive waits up to 2s for the next message on ch and checks its type.
func mustReceive[T pgproto3.FrontendMessage](t *testing.T, ch <-chan pgproto3.FrontendMessage) T {
	t.Helper()
	select {
	case msg := <-ch:
		got, ok := msg.(T)
		if !ok {
			t.Fatalf("upstream got %T; want %T", msg, *new(T))
		}
		return got
	case <-time.After(2 * time.Second):
		t.Fatalf("upstream got nothing in 2s; want %T", *new(T))
		panic("unreachable")
	}
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
