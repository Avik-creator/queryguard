package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5/pgproto3"
)

// Server message types and authentication codes RelayAuth acts on.
const (
	authRequestType   = 'R'
	errorResponseType = 'E'
	authOK            = 0
	authSASL          = 10
)

// RelayAuth copies server messages to client until authentication succeeds or fails, hiding channel binding mechanisms unless channelBinding.
func RelayAuth(client io.Writer, server io.Reader, channelBinding bool) error {
	for {
		// Message type, length, and for 'R' messages the authentication code.
		var head [9]byte
		if _, err := io.ReadFull(server, head[:5]); err != nil {
			return err
		}
		typ, size := head[0], int64(binary.BigEndian.Uint32(head[1:5]))-4
		if size < 0 {
			return fmt.Errorf("server message %q has invalid length %d", typ, size+4)
		}

		if typ != authRequestType {
			if err := forward(client, server, head[:5], size); err != nil {
				return err
			}
			if typ == errorResponseType {
				return nil
			}
			continue
		}

		if size < 4 {
			return fmt.Errorf("authentication message too short")
		}
		if _, err := io.ReadFull(server, head[5:]); err != nil {
			return unexpected(err)
		}
		code := binary.BigEndian.Uint32(head[5:])
		switch {
		case code == authOK:
			return forward(client, server, head[:], size-4)
		case code == authSASL && !channelBinding:
			if err := relaySASL(client, server, head[5:], size); err != nil {
				return err
			}
		default:
			if err := forward(client, server, head[:], size-4); err != nil {
				return err
			}
		}
	}
}

// relaySASL rewrites an AuthenticationSASL message of size bytes, whose code was already read, without -PLUS mechanisms.
func relaySASL(client io.Writer, server io.Reader, code []byte, size int64) error {
	if size > maxPacketLen {
		return fmt.Errorf("AuthenticationSASL of %d bytes is too long", size)
	}
	body := make([]byte, size)
	copy(body, code)
	if _, err := io.ReadFull(server, body[len(code):]); err != nil {
		return unexpected(err)
	}
	var msg pgproto3.AuthenticationSASL
	if err := msg.Decode(body); err != nil {
		return fmt.Errorf("invalid AuthenticationSASL: %w", err)
	}
	// Channel binding ties SCRAM to the TLS session, which ends at the proxy; SASL names such mechanisms with -PLUS.
	msg.AuthMechanisms = slices.DeleteFunc(msg.AuthMechanisms, func(m string) bool { return strings.HasSuffix(m, "-PLUS") })
	buf, err := msg.Encode(nil)
	if err != nil {
		return err
	}
	_, err = client.Write(buf)
	return err
}

// forward writes head to client, then copies the next n bytes from server.
func forward(client io.Writer, server io.Reader, head []byte, n int64) error {
	if _, err := client.Write(head); err != nil {
		return err
	}
	_, err := io.CopyN(client, server, n)
	return unexpected(err)
}

// unexpected turns io.EOF into io.ErrUnexpectedEOF, for reads that stop partway through a message.
func unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
