package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

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

func TestNegotiateDeclinesSSL(t *testing.T) {
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

	if _, err := Negotiate(rw(r, io.Discard)); err != nil {
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
			msg, rerr := pgproto3.NewFrontend(bytes.NewReader(bytes.TrimPrefix(out, []byte("N"))), nil).Receive()
			if rerr != nil {
				t.Fatalf("client got %q, not an ErrorResponse: %v", out, rerr)
			}
			got := mustBe[*pgproto3.ErrorResponse](t, msg)
			if got.Severity != "FATAL" || got.Code != tt.wantCode {
				t.Errorf("got %s %s %q; want FATAL %s", got.Severity, got.Code, got.Message, tt.wantCode)
			}
		})
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

// negotiate runs Negotiate on scripted client bytes and returns what it wrote back.
func negotiate(in []byte) (pgproto3.FrontendMessage, []byte, error) {
	var out bytes.Buffer
	msg, err := Negotiate(rw(bytes.NewReader(in), &out))
	return msg, out.Bytes(), err
}

func rw(r io.Reader, w io.Writer) io.ReadWriter {
	return struct {
		io.Reader
		io.Writer
	}{r, w}
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
