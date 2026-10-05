package wire

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5/pgproto3"
)

// Server message types and authentication codes RelayStartup acts on.
const (
	authRequestType     = 'R'
	backendKeyDataType  = 'K'
	parameterStatusType = 'S'
	readyForQueryType   = 'Z'
	errorResponseType   = 'E'
	authOK              = 0
	authSASL            = 10
)

// maxKeyDataLen is the longest BackendKeyData body: a process ID and a 256-byte secret, the protocol 3.2 limit.
const maxKeyDataLen = 4 + 256

// ErrLoginRefused says the server ended the login with an error, which the client has already been sent.
var ErrLoginRefused = errors.New("server refused the login")

// StartupOptions says how RelayStartup rewrites the server's startup messages.
type StartupOptions struct {
	ChannelBinding bool                                                           // keep -PLUS SASL mechanisms
	IssueKey       func(server *pgproto3.BackendKeyData) *pgproto3.BackendKeyData // the key data the client gets instead; nil keeps the server's
	Report         func(name, value string)                                       // gets each ParameterStatus; nil ignores them
	// Authenticated runs once AuthenticationOk has reached the client; an *Error it returns goes to the client as FATAL and ends the login.
	Authenticated func() *Error
}

// passwordMessageType is the client's password, SASL and GSSAPI replies during login.
const passwordMessageType = 'p'

// maxAuthReplyLen is the longest authentication reply Postgres reads, PG_MAX_AUTH_TOKEN_LENGTH.
const maxAuthReplyLen = 65535

// RelayAuthReplies copies the client's authentication replies to server until the client sends anything else, which it leaves unread.
func RelayAuthReplies(client *bufio.Reader, server io.Writer) error {
	for {
		head, err := client.Peek(5)
		if err != nil {
			return err
		}
		if head[0] != passwordMessageType {
			return nil
		}
		size := int64(binary.BigEndian.Uint32(head[1:])) - 4
		if size < 0 || size > maxAuthReplyLen {
			return fmt.Errorf("client message %q has invalid length %d", head[0], size+4)
		}
		var h [5]byte
		copy(h[:], head)
		client.Discard(5)
		if err := forward(server, client, h[:], size); err != nil {
			return err
		}
	}
}

// RelayStartup copies server messages to client until ReadyForQuery, or an ErrorResponse that refuses the login, reading nothing past it.
func RelayStartup(client io.Writer, server io.Reader, opts StartupOptions) error {
	hidBinding := false
	for {
		var head [5]byte
		if _, err := io.ReadFull(server, head[:]); err != nil {
			return err
		}
		typ, size := head[0], int64(binary.BigEndian.Uint32(head[1:]))-4
		if size < 0 {
			return fmt.Errorf("server message %q has invalid length %d", typ, size+4)
		}

		var err error
		switch {
		case typ == authRequestType:
			var hid bool
			hid, err = relayAuth(client, server, head, size, opts)
			hidBinding = hidBinding || hid
		case typ == backendKeyDataType && opts.IssueKey != nil:
			err = relayKey(client, server, size, opts.IssueKey)
		case typ == parameterStatusType && opts.Report != nil:
			err = relayParameter(client, server, head, size, opts.Report)
		case typ == errorResponseType && size <= maxPacketLen:
			return relayRefusal(client, server, head, size, hidBinding)
		default:
			err = forward(client, server, head[:], size)
		}
		if err != nil {
			return err
		}
		switch typ {
		case readyForQueryType:
			return nil
		case errorResponseType:
			return ErrLoginRefused
		}
	}
}

// LoginRefusedError is ErrLoginRefused with the SQLSTATE Postgres gave, such as 28P01 for a wrong password.
type LoginRefusedError struct{ Code string }

func (e *LoginRefusedError) Error() string { return ErrLoginRefused.Error() + ": " + e.Code }

func (e *LoginRefusedError) Is(target error) bool { return target == ErrLoginRefused }

// bindingHint explains Postgres's refusal of a client that saw no -PLUS mechanism but could have bound to the proxy's TLS session.
const bindingHint = "QueryGuard ends TLS, so SCRAM channel binding can't reach Postgres: connect with channel_binding=disable, " +
	"or give QueryGuard Postgres's own certificate and key."

// relayRefusal forwards the ErrorResponse that ends a login, with a hint when hidBinding led to a protocol violation, and returns it as a LoginRefusedError.
func relayRefusal(client io.Writer, server io.Reader, head [5]byte, size int64, hidBinding bool) error {
	body := make([]byte, size)
	if _, err := io.ReadFull(server, body); err != nil {
		return unexpected(err)
	}
	var e pgproto3.ErrorResponse
	if err := e.Decode(body); err != nil {
		if _, err := client.Write(append(head[:], body...)); err != nil {
			return err
		}
		return ErrLoginRefused
	}
	// Postgres over TLS refuses SCRAM's "y" flag, which libpq and pgx send over TLS when offered no -PLUS mechanism, with 28000.
	if hidBinding && e.Hint == "" && (e.Code == "08P01" || e.Code == "28000" && strings.Contains(e.Message, "channel binding")) {
		e.Hint = bindingHint
		if err := writeMessage(client, &e); err != nil {
			return err
		}
	} else if _, err := client.Write(append(head[:], body...)); err != nil {
		return err
	}
	return &LoginRefusedError{Code: e.Code}
}

// relayAuth forwards an authentication request of size bytes, removing -PLUS mechanisms from AuthenticationSASL
// unless opts allow channel binding, and runs opts.Authenticated after AuthenticationOk; it reports whether it removed any.
func relayAuth(client io.Writer, server io.Reader, head [5]byte, size int64, opts StartupOptions) (bool, error) {
	if size < 4 {
		return false, fmt.Errorf("authentication message too short")
	}
	body := make([]byte, 4, min(size, maxPacketLen))
	if _, err := io.ReadFull(server, body); err != nil {
		return false, unexpected(err)
	}
	switch code := binary.BigEndian.Uint32(body); {
	case code == authOK && opts.Authenticated != nil:
		if err := forward(client, server, append(head[:], body...), size-4); err != nil {
			return false, err
		}
		if e := opts.Authenticated(); e != nil {
			return false, fail(client, e.Code, e.Message)
		}
		return false, nil
	case code != authSASL || opts.ChannelBinding:
		return false, forward(client, server, append(head[:], body...), size-4)
	}

	if size > maxPacketLen {
		return false, fmt.Errorf("AuthenticationSASL of %d bytes is too long", size)
	}
	body = body[:size]
	if _, err := io.ReadFull(server, body[4:]); err != nil {
		return false, unexpected(err)
	}
	var msg pgproto3.AuthenticationSASL
	if err := msg.Decode(body); err != nil {
		return false, fmt.Errorf("invalid AuthenticationSASL: %w", err)
	}
	// Channel binding ties SCRAM to the TLS session, which ends at the proxy; SASL names such mechanisms with -PLUS.
	n := len(msg.AuthMechanisms)
	msg.AuthMechanisms = slices.DeleteFunc(msg.AuthMechanisms, func(m string) bool { return strings.HasSuffix(m, "-PLUS") })
	return len(msg.AuthMechanisms) < n, writeMessage(client, &msg)
}

// relayKey replaces a BackendKeyData message of size bytes with the key data issueKey returns.
func relayKey(client io.Writer, server io.Reader, size int64, issueKey func(*pgproto3.BackendKeyData) *pgproto3.BackendKeyData) error {
	if size > maxKeyDataLen {
		return fmt.Errorf("BackendKeyData of %d bytes is too long", size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(server, body); err != nil {
		return unexpected(err)
	}
	var key pgproto3.BackendKeyData
	if err := key.Decode(body); err != nil {
		return fmt.Errorf("invalid BackendKeyData: %w", err)
	}
	return writeMessage(client, issueKey(&key))
}

// relayParameter forwards a ParameterStatus of size bytes after passing it to report.
func relayParameter(client io.Writer, server io.Reader, head [5]byte, size int64, report func(name, value string)) error {
	if size > maxPacketLen {
		return fmt.Errorf("ParameterStatus of %d bytes is too long", size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(server, body); err != nil {
		return unexpected(err)
	}
	var msg pgproto3.ParameterStatus
	if err := msg.Decode(body); err != nil {
		return fmt.Errorf("invalid ParameterStatus: %w", err)
	}
	report(msg.Name, msg.Value)
	_, err := client.Write(append(head[:], body...))
	return err
}

// writeMessage encodes msg and writes it to w.
func writeMessage(w io.Writer, msg pgproto3.BackendMessage) error {
	buf, err := msg.Encode(nil)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
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
