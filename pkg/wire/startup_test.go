package wire

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Avik-creator/queryguard/internal/testcert"
	"github.com/jackc/pgx/v5/pgproto3"
)

func TestNegotiateReturnsStartupMessage(t *testing.T) {
	in := encode(t, startup(pgproto3.ProtocolVersion30, "user", "alice", "database", "shop"))

	msg, out, err := negotiate(in)

	if err != nil {
		t.Fatal(err)
	}
	got := mustBe[*pgproto3.StartupMessage](t, msg)
	if got.ProtocolVersion != pgproto3.ProtocolVersion30 || got.Parameters["user"] != "alice" || got.Parameters["database"] != "shop" {
		t.Errorf("got %+v; want protocol 3.0, user alice, database shop", got)
	}
	if len(out) != 0 {
		t.Errorf("wrote %q to the client; want nothing", out)
	}
}

func TestNegotiateDeclinesSSLWithoutTLSConfig(t *testing.T) {
	in := concat(encode(t, &pgproto3.SSLRequest{}), encode(t, startup(pgproto3.ProtocolVersion30, "user", "alice")))

	msg, out, err := negotiate(in)

	if err != nil {
		t.Fatal(err)
	}
	mustBe[*pgproto3.StartupMessage](t, msg)
	if string(out) != "N" {
		t.Errorf("replied %q; want %q", out, "N")
	}
}

func TestNegotiateDeclinesGSSEncryption(t *testing.T) {
	in := concat(encode(t, &pgproto3.GSSEncRequest{}), encode(t, startup(pgproto3.ProtocolVersion30, "user", "alice")))

	msg, out, err := negotiate(in)

	if err != nil {
		t.Fatal(err)
	}
	mustBe[*pgproto3.StartupMessage](t, msg)
	if string(out) != "N" {
		t.Errorf("replied %q; want %q", out, "N")
	}
}

func TestNegotiateReturnsCancelRequestWithLongKey(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	in := encode(t, &pgproto3.CancelRequest{ProcessID: 42, SecretKey: key})

	msg, _, err := negotiate(in)

	if err != nil {
		t.Fatal(err)
	}
	got := mustBe[*pgproto3.CancelRequest](t, msg)
	if got.ProcessID != 42 || !bytes.Equal(got.SecretKey, key) {
		t.Errorf("got %+v; want process 42 and the 32-byte key", got)
	}
}

func TestNegotiateKeepsUnknownMinorVersion(t *testing.T) {
	const v33 = 3<<16 | 3
	in := encode(t, startup(v33, "user", "alice"))

	msg, _, err := negotiate(in)

	if err != nil {
		t.Fatal(err)
	}
	got := mustBe[*pgproto3.StartupMessage](t, msg)
	if got.ProtocolVersion != v33 || got.Parameters["user"] != "alice" {
		t.Errorf("got %+v; want protocol 3.3 kept for the server to negotiate", got)
	}
}

func TestNegotiateDoesNotReadPastStartup(t *testing.T) {
	in := concat(encode(t, startup(pgproto3.ProtocolVersion30, "user", "alice")), []byte("next"))
	r := bytes.NewReader(in)

	if _, _, err := Negotiate(scriptConn{r: r, w: io.Discard}, nil); err != nil {
		t.Fatal(err)
	}
	if rest, _ := io.ReadAll(r); string(rest) != "next" {
		t.Errorf("left %q unread; want %q", rest, "next")
	}
}

func TestNegotiateReturnsEOFWhenClientSendsNothing(t *testing.T) {
	_, out, err := negotiate(nil)

	if !errors.Is(err, io.EOF) {
		t.Errorf("got error %v; want io.EOF", err)
	}
	if len(out) != 0 {
		t.Errorf("wrote %q to the client; want nothing", out)
	}
}

func TestNegotiateRejects(t *testing.T) {
	tests := []struct {
		name     string
		in       []byte
		wantCode string
	}{
		{"protocol 2.0", encode(t, startup(2<<16, "user", "alice")), "0A000"},
		{"missing user", encode(t, startup(pgproto3.ProtocolVersion30, "database", "shop")), "28000"},
		{"second SSL request", concat(encode(t, &pgproto3.SSLRequest{}), encode(t, &pgproto3.SSLRequest{})), "08P01"},
		{"length too short", packet(4), "08P01"},
		{"length too long", packet(10_001), "08P01"},
		{"unterminated parameters", concat(packet(13), u32(pgproto3.ProtocolVersion30), []byte("user\x00al")), "08P01"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, out, err := negotiate(tt.in)

			if _, ok := errors.AsType[*Error](err); !ok {
				t.Fatalf("got error %v; want *wire.Error", err)
			}
			expectFatal(t, bytes.NewReader(bytes.TrimPrefix(out, []byte("N"))), tt.wantCode)
		})
	}
}

func TestNegotiateUpgradesSSLRequestToTLS(t *testing.T) {
	cert, clientTLS := testcert.Pair(t)
	client, done := negotiateTCP(t, ServerTLSConfig(cert))

	write(t, client, encode(t, &pgproto3.SSLRequest{}))
	expectReply(t, client, 'S')
	tc := tls.Client(client, clientTLS)
	write(t, tc, encode(t, startup(pgproto3.ProtocolVersion30, "user", "alice")))

	r := wait(t, done)
	if r.err != nil {
		t.Fatal(r.err)
	}
	if _, ok := r.conn.(*tls.Conn); !ok {
		t.Errorf("got %T back; want *tls.Conn", r.conn)
	}
	mustBe[*pgproto3.StartupMessage](t, r.msg)
}

func TestNegotiateAcceptsDirectTLS(t *testing.T) {
	cert, clientTLS := testcert.Pair(t)
	client, done := negotiateTCP(t, ServerTLSConfig(cert))

	clientTLS.NextProtos = []string{"postgresql"}
	tc := tls.Client(client, clientTLS)
	write(t, tc, encode(t, startup(pgproto3.ProtocolVersion30, "user", "alice")))

	r := wait(t, done)
	if r.err != nil {
		t.Fatal(r.err)
	}
	if _, ok := r.conn.(*tls.Conn); !ok {
		t.Errorf("got %T back; want *tls.Conn", r.conn)
	}
	mustBe[*pgproto3.StartupMessage](t, r.msg)
}

func TestNegotiateRejectsDirectTLSWithoutALPN(t *testing.T) {
	cert, clientTLS := testcert.Pair(t)
	client, done := negotiateTCP(t, ServerTLSConfig(cert))

	tc := tls.Client(client, clientTLS)
	write(t, tc, encode(t, startup(pgproto3.ProtocolVersion30, "user", "alice")))

	r := wait(t, done)
	if e, ok := errors.AsType[*Error](r.err); !ok || e.Code != "08P01" {
		t.Fatalf("got %v; want *wire.Error 08P01", r.err)
	}
	tc.SetReadDeadline(time.Now().Add(2 * time.Second))
	expectFatal(t, tc, "08P01")
}

func TestNegotiateClosesDirectTLSWithoutTLSConfig(t *testing.T) {
	_, clientTLS := testcert.Pair(t)
	client, done := negotiateTCP(t, nil)

	clientTLS.NextProtos = []string{"postgresql"}
	go tls.Client(client, clientTLS).Handshake()

	if r := wait(t, done); r.err == nil || r.msg != nil {
		t.Fatalf("got message %v, error %v; want an error", r.msg, r.err)
	}
}

func TestNegotiateRejectsPlaintextSentBeforeTLSHandshake(t *testing.T) {
	cert, _ := testcert.Pair(t)
	client, done := negotiateTCP(t, ServerTLSConfig(cert))

	// An attacker in the middle could inject plaintext here; it must never be read as the startup message.
	write(t, client, concat(encode(t, &pgproto3.SSLRequest{}), encode(t, startup(pgproto3.ProtocolVersion30, "user", "mallory"))))

	if r := wait(t, done); r.err == nil || r.msg != nil {
		t.Fatalf("got message %v, error %v; want the TLS handshake to fail", r.msg, r.err)
	}
}

func TestNegotiateRejectsSSLRequestInsideTLS(t *testing.T) {
	cert, clientTLS := testcert.Pair(t)
	client, done := negotiateTCP(t, ServerTLSConfig(cert))

	write(t, client, encode(t, &pgproto3.SSLRequest{}))
	expectReply(t, client, 'S')
	tc := tls.Client(client, clientTLS)
	write(t, tc, encode(t, &pgproto3.SSLRequest{}))

	if e, ok := errors.AsType[*Error](wait(t, done).err); !ok || e.Code != "08P01" {
		t.Fatalf("got %v; want *wire.Error 08P01", e)
	}
}

func TestNegotiateReturnsCancelRequestOverTLS(t *testing.T) {
	cert, clientTLS := testcert.Pair(t)
	client, done := negotiateTCP(t, ServerTLSConfig(cert))

	write(t, client, encode(t, &pgproto3.SSLRequest{}))
	expectReply(t, client, 'S')
	tc := tls.Client(client, clientTLS)
	write(t, tc, encode(t, &pgproto3.CancelRequest{ProcessID: 42, SecretKey: []byte{1, 2, 3, 4}}))

	r := wait(t, done)
	if r.err != nil {
		t.Fatal(r.err)
	}
	if got := mustBe[*pgproto3.CancelRequest](t, r.msg); got.ProcessID != 42 {
		t.Errorf("got process %d; want 42", got.ProcessID)
	}
}

func FuzzNegotiate(f *testing.F) {
	f.Add(encodeF(f, startup(pgproto3.ProtocolVersion32, "user", "alice")))
	f.Add(encodeF(f, &pgproto3.CancelRequest{ProcessID: 1, SecretKey: []byte{1, 2, 3, 4}}))
	f.Add(concat(encodeF(f, &pgproto3.SSLRequest{}), encodeF(f, startup(pgproto3.ProtocolVersion30, "user", "bob"))))
	f.Add(concat(packet(12), u32(80877102), u32(1)))
	f.Fuzz(func(t *testing.T, in []byte) {
		msg, _, err := negotiate(in)
		if (msg == nil) == (err == nil) {
			t.Fatalf("got message %v and error %v; want exactly one", msg, err)
		}
	})
}

// negotiate runs Negotiate without TLS on scripted client bytes and returns what it wrote back.
func negotiate(in []byte) (pgproto3.FrontendMessage, []byte, error) {
	var out bytes.Buffer
	_, msg, err := Negotiate(scriptConn{r: bytes.NewReader(in), w: &out}, nil)
	return msg, out.Bytes(), err
}

// scriptConn is a net.Conn that reads scripted client bytes and records replies; only Read and Write work.
type scriptConn struct {
	net.Conn
	r io.Reader
	w io.Writer
}

func (c scriptConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c scriptConn) Write(p []byte) (int, error) { return c.w.Write(p) }

type result struct {
	conn net.Conn
	msg  pgproto3.FrontendMessage
	err  error
}

// negotiateTCP runs Negotiate on the server end of a loopback TCP connection and returns the client end.
func negotiateTCP(t *testing.T, cfg *tls.Config) (net.Conn, <-chan result) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	server.SetDeadline(time.Now().Add(2 * time.Second))

	done := make(chan result, 1)
	go func() {
		conn, msg, err := Negotiate(server, cfg)
		if err != nil {
			server.Close()
		}
		done <- result{conn, msg, err}
	}()
	return client, done
}

func wait(t *testing.T, done <-chan result) result {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("Negotiate did not return within 3s")
		return result{}
	}
}

func write(t *testing.T, w io.Writer, b []byte) {
	t.Helper()
	if _, err := w.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// expectReply reads one byte from conn and checks it is want.
func expectReply(t *testing.T, conn net.Conn, want byte) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	if _, err := io.ReadFull(conn, b[:]); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	conn.SetReadDeadline(time.Time{})
	if b[0] != want {
		t.Fatalf("got reply %q; want %q", b[0], want)
	}
}

// expectFatal reads an ErrorResponse from r and checks it is FATAL with the given SQLSTATE.
func expectFatal(t *testing.T, r io.Reader, code string) {
	t.Helper()
	msg, err := pgproto3.NewFrontend(r, nil).Receive()
	if err != nil {
		t.Fatalf("want an ErrorResponse: %v", err)
	}
	got := mustBe[*pgproto3.ErrorResponse](t, msg)
	if got.Severity != "FATAL" || got.Code != code {
		t.Errorf("got %s %s %q; want FATAL %s", got.Severity, got.Code, got.Message, code)
	}
}

// startup builds a StartupMessage from a version and name/value pairs.
func startup(version uint32, kv ...string) *pgproto3.StartupMessage {
	params := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		params[kv[i]] = kv[i+1]
	}
	return &pgproto3.StartupMessage{ProtocolVersion: version, Parameters: params}
}

type encoder interface{ Encode([]byte) ([]byte, error) }

func encode(t *testing.T, m encoder) []byte {
	t.Helper()
	b, err := m.Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func encodeF(f *testing.F, m encoder) []byte {
	b, err := m.Encode(nil)
	if err != nil {
		f.Fatal(err)
	}
	return b
}

// packet returns just a length word, for building malformed packets by hand.
func packet(length uint32) []byte { return u32(length) }

func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func concat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func mustBe[T any](t *testing.T, msg any) T {
	t.Helper()
	got, ok := msg.(T)
	if !ok {
		t.Fatalf("got %T; want %T", msg, *new(T))
	}
	return got
}
