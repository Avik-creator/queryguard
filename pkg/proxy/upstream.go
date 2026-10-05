package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"

	"github.com/jackc/pgx/v5/pgproto3"
)

// Upstream hands out server connections; a connection pool can implement it later.
type Upstream interface {
	// Acquire returns a server connection that has been sent startup.
	Acquire(ctx context.Context, startup *pgproto3.StartupMessage) (net.Conn, error)
	// Release gives back a connection from Acquire once its client is done.
	Release(conn net.Conn)
	// Cancel delivers a client's CancelRequest to the server, returning once the server has acted on it.
	Cancel(ctx context.Context, req *pgproto3.CancelRequest) error
}

// Dialer is the Upstream that opens a new server connection for every client.
type Dialer struct {
	Addr      string      // host:port of the Postgres server
	TLSConfig *tls.Config // nil means plaintext; otherwise TLS is required

	KeepAlive net.KeepAliveConfig // a disabled config keeps Go's defaults
}

func (d Dialer) Acquire(ctx context.Context, startup *pgproto3.StartupMessage) (net.Conn, error) {
	conn, err := d.dial(ctx)
	if err != nil {
		return nil, err
	}
	if err := writeMessage(conn, startup); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (d Dialer) Release(conn net.Conn) { conn.Close() }

func (d Dialer) Cancel(ctx context.Context, req *pgproto3.CancelRequest) error {
	conn, err := d.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := writeMessage(conn, req); err != nil {
		return err
	}
	// Postgres closes the connection once it has signalled the backend, so until then a statement sent next could get the cancel.
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetReadDeadline(deadline)
	}
	_, err = io.Copy(io.Discard, conn)
	return err
}

func (d Dialer) dial(ctx context.Context) (net.Conn, error) {
	var nd net.Dialer
	conn, err := nd.DialContext(ctx, "tcp", d.Addr)
	if err != nil {
		return nil, err
	}
	if err := setKeepAlive(conn, d.KeepAlive); err != nil {
		conn.Close()
		return nil, err
	}
	if d.TLSConfig == nil {
		return conn, nil
	}
	tlsConn, err := startTLS(ctx, conn, d.TLSConfig)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// startTLS sends an SSLRequest on conn and, if the server agrees, runs the TLS handshake.
func startTLS(ctx context.Context, conn net.Conn, cfg *tls.Config) (net.Conn, error) {
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	if err := writeMessage(conn, &pgproto3.SSLRequest{}); err != nil {
		return nil, err
	}
	var reply [1]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return nil, err
	}
	if reply[0] != 'S' {
		return nil, errors.New("server does not support TLS")
	}
	// Only the reply byte was read, so plaintext the server sent after it can't slip into the TLS session.
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

// writeMessage encodes msg and writes it to conn.
func writeMessage(conn net.Conn, msg interface{ Encode([]byte) ([]byte, error) }) error {
	buf, err := msg.Encode(nil)
	if err != nil {
		return err
	}
	_, err = conn.Write(buf)
	return err
}
