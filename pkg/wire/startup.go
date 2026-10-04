// Package wire handles the Postgres wire protocol between clients, the proxy and the server.
package wire

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5/pgproto3"
)

// Request codes that can take the place of a protocol version in a startup packet.
const (
	sslRequestCode    = 80877103
	gssEncRequestCode = 80877104
	cancelRequestCode = 80877102
)

// Startup packet length limits, including the length word; the maximum matches Postgres.
const (
	minPacketLen = 8
	maxPacketLen = 10_000
)

// tlsHandshakeByte starts every TLS connection; a startup packet's first byte is always 0.
const tlsHandshakeByte = 0x16

// alpnProtocol is the ALPN name Postgres requires for direct TLS (PG17+).
const alpnProtocol = "postgresql"

// Error is a startup failure that has already been reported to the client.
type Error struct {
	Code    string // SQLSTATE
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("%s (SQLSTATE %s)", e.Message, e.Code) }

// ServerTLSConfig returns a config for accepting client TLS with cert, including the ALPN direct TLS needs.
func ServerTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{alpnProtocol},
	}
}

// Negotiate runs the startup handshake and returns the connection to use from now on and the client's StartupMessage or CancelRequest.
func Negotiate(conn net.Conn, tlsConfig *tls.Config) (net.Conn, pgproto3.FrontendMessage, error) {
	var first [1]byte
	if _, err := io.ReadFull(conn, first[:]); err != nil {
		return nil, nil, err
	}
	if first[0] == tlsHandshakeByte {
		return directTLS(conn, first[0], tlsConfig)
	}
	return readStartup(conn, first[:], tlsConfig, false)
}

// directTLS completes a TLS handshake the client started without an SSLRequest.
func directTLS(conn net.Conn, first byte, tlsConfig *tls.Config) (net.Conn, pgproto3.FrontendMessage, error) {
	if tlsConfig == nil {
		return nil, nil, errors.New("client started TLS but TLS is not configured")
	}
	tlsConn := tls.Server(&prefixConn{Conn: conn, prefix: []byte{first}}, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, nil, err
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != alpnProtocol {
		return nil, nil, fail(tlsConn, "08P01", "received direct SSL connection request without ALPN protocol negotiation extension")
	}
	return readStartup(tlsConn, nil, tlsConfig, true)
}

// readStartup reads startup packets until a StartupMessage or CancelRequest; header holds bytes of the first packet already read.
func readStartup(conn net.Conn, header []byte, tlsConfig *tls.Config, encrypted bool) (net.Conn, pgproto3.FrontendMessage, error) {
	var sawSSL, sawGSS bool
	for {
		body, err := readPacket(conn, header)
		if err != nil {
			return nil, nil, err
		}
		header = nil
		code := binary.BigEndian.Uint32(body)

		switch {
		case code == sslRequestCode && !encrypted && !sawSSL && tlsConfig != nil:
			if _, err := conn.Write([]byte{'S'}); err != nil {
				return nil, nil, err
			}
			// Nothing past the SSLRequest has been read, so injected plaintext can't survive into the TLS session.
			tlsConn := tls.Server(conn, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				return nil, nil, err
			}
			conn, encrypted = tlsConn, true
		case code == sslRequestCode && !encrypted && !sawSSL:
			sawSSL = true
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return nil, nil, err
			}
		case code == gssEncRequestCode && !encrypted && !sawGSS:
			sawGSS = true
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return nil, nil, err
			}
		case code == sslRequestCode || code == gssEncRequestCode:
			return nil, nil, fail(conn, "08P01", "duplicate encryption request")
		case code == cancelRequestCode:
			var req pgproto3.CancelRequest
			if err := req.Decode(body); err != nil {
				return nil, nil, fail(conn, "08P01", "invalid cancel request: "+err.Error())
			}
			return conn, &req, nil
		case code>>16 == 3:
			// Not returned directly: a nil *StartupMessage would make a non-nil interface.
			msg, err := decodeStartup(conn, code, body)
			if err != nil {
				return nil, nil, err
			}
			return conn, msg, nil
		default:
			return nil, nil, fail(conn, "0A000", fmt.Sprintf("unsupported frontend protocol %d.%d: queryguard supports 3.x", code>>16, code&0xffff))
		}
	}
}

// decodeStartup decodes any 3.x StartupMessage, keeping its version for the server to negotiate.
func decodeStartup(conn io.Writer, version uint32, body []byte) (*pgproto3.StartupMessage, error) {
	// pgproto3 only decodes 3.0 and 3.2, so decode other minor versions as 3.0.
	binary.BigEndian.PutUint32(body, pgproto3.ProtocolVersion30)
	var msg pgproto3.StartupMessage
	if err := msg.Decode(body); err != nil {
		return nil, fail(conn, "08P01", "invalid startup packet layout")
	}
	msg.ProtocolVersion = version
	if msg.Parameters["user"] == "" {
		return nil, fail(conn, "28000", "no PostgreSQL user name specified in startup packet")
	}
	return &msg, nil
}

// readPacket reads exactly one startup packet, after the header bytes already read, and returns it without the length word.
func readPacket(conn io.ReadWriter, header []byte) ([]byte, error) {
	var buf [4]byte
	n := copy(buf[:], header)
	if _, err := io.ReadFull(conn, buf[n:]); err != nil {
		if n > 0 && errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	length := int32(binary.BigEndian.Uint32(buf[:]))
	if length < minPacketLen || length > maxPacketLen {
		return nil, fail(conn, "08P01", "invalid length of startup packet")
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, unexpected(err)
	}
	return body, nil
}

// prefixConn replays bytes already read from Conn before reading more.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// fail sends a FATAL error to the client and returns it as an *Error.
func fail(w io.Writer, code, msg string) error {
	_ = SendFatal(w, code, msg)
	return &Error{Code: code, Message: msg}
}

// SendFatal writes a FATAL ErrorResponse to w.
func SendFatal(w io.Writer, code, msg string) error {
	buf, err := (&pgproto3.ErrorResponse{Severity: "FATAL", SeverityUnlocalized: "FATAL", Code: code, Message: msg}).Encode(nil)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}

// notSettings are the startup parameters Postgres handles itself instead of as settings.
var notSettings = []string{"user", "database", "options", "replication"}

// switchesWithValue are the postgres switches that take a value, from process_postgres_switches in postgres.c.
const switchesWithValue = "BCcDdfhkNprStvW-"

// StartupSettings yields the settings a startup message asks for, from options (-c name=value and --name=value)
// and then the other parameters, with names lower-cased and dashes made underscores as Postgres matches them.
func StartupSettings(params map[string]string) iter.Seq2[string, string] {
	return func(yield func(string, string) bool) {
		args := splitOptions(params["options"])
		for i := 0; i < len(args); i++ {
			// Postgres refuses a word that is not a switch, so whatever follows it is never applied.
			if len(args[i]) < 2 || args[i][0] != '-' {
				return
			}
			for j := 1; j < len(args[i]); j++ {
				sw := args[i][j]
				if !strings.ContainsRune(switchesWithValue, rune(sw)) {
					continue
				}
				value := args[i][j+1:]
				if value == "" && i+1 < len(args) {
					i++
					value = args[i]
				}
				if name, v, ok := strings.Cut(value, "="); ok && (sw == 'c' || sw == '-') {
					if !yield(strings.ToLower(strings.ReplaceAll(name, "-", "_")), v) {
						return
					}
				}
				break
			}
		}
		for name, value := range params {
			if !slices.Contains(notSettings, name) && !strings.HasPrefix(name, "_pq_.") && !yield(strings.ToLower(name), value) {
				return
			}
		}
	}
}

// splitOptions splits options into words at unescaped white space, as pg_split_opts in postinit.c does.
func splitOptions(options string) []string {
	var words []string
	var word strings.Builder
	inWord, escaped := false, false
	for i := range len(options) {
		c := options[i]
		switch {
		case escaped:
			escaped = false
			word.WriteByte(c)
		case strings.IndexByte(" \t\n\v\f\r", c) >= 0:
			if inWord {
				words = append(words, word.String())
				word.Reset()
			}
			inWord = false
			continue
		case c == '\\':
			escaped = true
		default:
			word.WriteByte(c)
		}
		inWord = true
	}
	if inWord {
		words = append(words, word.String())
	}
	return words
}
