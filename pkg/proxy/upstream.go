package proxy

import (
	"context"
	"net"

	"github.com/jackc/pgx/v5/pgproto3"
)

// Upstream hands out server connections; a connection pool can implement it later.
type Upstream interface {
	// Acquire returns a server connection that has been sent startup.
	Acquire(ctx context.Context, startup *pgproto3.StartupMessage) (net.Conn, error)
	// Release gives back a connection from Acquire once its client is done.
	Release(conn net.Conn)
	// Cancel delivers a client's CancelRequest to the server.
	Cancel(ctx context.Context, req *pgproto3.CancelRequest) error
}

// Dialer is the Upstream that opens a new server connection for every client.
type Dialer struct {
	Addr string // host:port of the Postgres server
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
	return writeMessage(conn, req)
}

func (d Dialer) dial(ctx context.Context) (net.Conn, error) {
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", d.Addr)
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
