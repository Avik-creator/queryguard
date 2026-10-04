// Package wire handles the Postgres wire protocol between clients, the proxy and the server.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

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

// Error is a startup failure that has already been reported to the client.
type Error struct {
	Code    string // SQLSTATE
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("%s (SQLSTATE %s)", e.Message, e.Code) }

// Negotiate declines SSL and GSS encryption and returns the client's StartupMessage or CancelRequest.
func Negotiate(conn io.ReadWriter) (pgproto3.FrontendMessage, error) {
	var sawSSL, sawGSS bool
	for {
		body, err := readPacket(conn)
		if err != nil {
			return nil, err
		}
		code := binary.BigEndian.Uint32(body)

		switch {
		case code == sslRequestCode && !sawSSL:
			sawSSL = true
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return nil, err
			}
		case code == gssEncRequestCode && !sawGSS:
			sawGSS = true
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return nil, err
			}
		case code == sslRequestCode || code == gssEncRequestCode:
			return nil, fail(conn, "08P01", "duplicate encryption request")
		case code == cancelRequestCode:
			var req pgproto3.CancelRequest
			if err := req.Decode(body); err != nil {
				return nil, fail(conn, "08P01", "invalid cancel request: "+err.Error())
			}
			return &req, nil
		case code>>16 == 3:
			// Not returned directly: a nil *StartupMessage would make a non-nil interface.
			msg, err := decodeStartup(conn, code, body)
			if err != nil {
				return nil, err
			}
			return msg, nil
		default:
			return nil, fail(conn, "0A000", fmt.Sprintf("unsupported frontend protocol %d.%d: queryguard supports 3.x", code>>16, code&0xffff))
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

// readPacket reads exactly one length-prefixed startup packet and returns it without the length word.
func readPacket(conn io.ReadWriter) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	n := int32(binary.BigEndian.Uint32(header[:]))
	if n < minPacketLen || n > maxPacketLen {
		return nil, fail(conn, "08P01", "invalid length of startup packet")
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return body, nil
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
