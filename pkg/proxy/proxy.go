// Package proxy relays each client connection to its own upstream Postgres connection.
package proxy

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Avik-creator/queryguard/pkg/wire"
	"github.com/jackc/pgx/v5/pgproto3"
)

// Defaults used when the matching Server field is zero.
const (
	DefaultStartupTimeout  = 10 * time.Second
	DefaultShutdownTimeout = 30 * time.Second
)

// DefaultClientCheckInterval is the suggested ClientCheckInterval; zero there means off.
const DefaultClientCheckInterval = 2 * time.Second

// checkIntervalParam makes Postgres poll the socket during a query and stop it once the connection is closed.
const checkIntervalParam = "client_connection_check_interval"

// Server relays client connections to Upstream, one server connection per client.
type Server struct {
	Upstream        Upstream
	TLSConfig       *tls.Config   // nil means clients are told TLS is unavailable
	StartupTimeout  time.Duration // how long a new client has to send its startup message
	ShutdownTimeout time.Duration // how long sessions may drain after Serve stops
	Logger          *slog.Logger  // nil means slog.Default()

	// ClientCheckInterval is sent as client_connection_check_interval unless the client set it; 0 sends nothing.
	ClientCheckInterval time.Duration

	keys cancelKeys
}

// Serve accepts on ln until ctx is cancelled, then drains sessions for up to ShutdownTimeout.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	log := cmp.Or(s.Logger, slog.Default())

	// Closing the listener unblocks Accept once ctx is cancelled.
	stopAccepting := context.AfterFunc(ctx, func() { ln.Close() })
	defer stopAccepting()

	// Sessions outlive ctx while draining; this context ends them when the timeout runs out.
	sessionCtx, closeSessions := context.WithCancel(context.WithoutCancel(ctx))
	defer closeSessions()

	var sessions sync.WaitGroup
	for {
		client, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				// The listener failed on its own, not because we stopped it.
				closeSessions()
				sessions.Wait()
				return err
			}
			break
		}
		sessions.Go(func() { s.handle(sessionCtx, log, client) })
	}

	drained := make(chan struct{})
	go func() {
		sessions.Wait()
		close(drained)
	}()

	timeout := cmp.Or(s.ShutdownTimeout, DefaultShutdownTimeout)
	select {
	case <-drained:
	case <-time.After(timeout):
		log.Warn("closing open sessions after shutdown timeout", "timeout", timeout)
		closeSessions()
		<-drained
	}
	return nil
}

// handle reads the client's startup packet and either forwards a cancel or starts a session.
func (s *Server) handle(ctx context.Context, log *slog.Logger, client net.Conn) {
	defer client.Close()
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()

	// The deadline covers the TLS handshake too, since the TLS connection reads through client.
	client.SetDeadline(time.Now().Add(cmp.Or(s.StartupTimeout, DefaultStartupTimeout)))
	conn, msg, err := wire.Negotiate(client, s.TLSConfig)
	if err != nil {
		// A client that connects and leaves without a word, like a TCP health check, is not an error.
		if !errors.Is(err, io.EOF) {
			log.Warn("client startup failed", "client", client.RemoteAddr(), "err", err)
		}
		return
	}
	client.SetDeadline(time.Time{})

	switch msg := msg.(type) {
	case *pgproto3.CancelRequest:
		req, ok := s.keys.lookup(msg)
		if !ok {
			log.Info("ignored cancel request with unknown key", "client", client.RemoteAddr())
			return
		}
		if err := s.Upstream.Cancel(ctx, req); err != nil {
			log.Warn("forward cancel request", "client", client.RemoteAddr(), "err", err)
		}
	case *pgproto3.StartupMessage:
		s.relay(ctx, log, conn, msg)
	}
}

// relay connects client to an upstream connection and copies bytes both ways until either side closes.
func (s *Server) relay(ctx context.Context, log *slog.Logger, client net.Conn, startup *pgproto3.StartupMessage) {
	s.addCheckInterval(startup)
	server, err := s.Upstream.Acquire(ctx, startup)
	if err != nil {
		log.Error("connect to upstream", "client", client.RemoteAddr(), "err", err)
		wire.SendFatal(client, "08006", "queryguard: cannot connect to the database server")
		return
	}
	defer s.Upstream.Release(server)

	// The startup copy sets forget; it is called once both copies are done.
	forget := func() {}
	opts := wire.StartupOptions{
		ChannelBinding: sameCertificate(client, server, s.TLSConfig),
		IssueKey: func(key *pgproto3.BackendKeyData) *pgproto3.BackendKeyData {
			forget()
			issued, f := s.keys.issue(key)
			forget = f
			return issued
		},
	}
	closeBoth := func() {
		client.Close()
		server.Close()
	}
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()

	// When one side stops, close both so the other copy ends too.
	var copies sync.WaitGroup
	copies.Go(func() {
		io.Copy(server, client)
		closeBoth()
	})
	copies.Go(func() {
		err := wire.RelayStartup(client, server, opts)
		if err == nil {
			io.Copy(client, server)
		} else if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			// Either side hanging up mid-login is normal; psql does it before every password prompt.
			log.Warn("relay startup", "client", client.RemoteAddr(), "err", err)
		}
		closeBoth()
	})
	copies.Wait()
	forget()
}

// addCheckInterval sets client_connection_check_interval in startup unless the client set it, directly or in options.
func (s *Server) addCheckInterval(startup *pgproto3.StartupMessage) {
	ms := s.ClientCheckInterval.Milliseconds()
	if ms <= 0 {
		return
	}
	// A startup parameter beats the same setting in options, so ours would silently replace the client's.
	if _, set := startup.Parameters[checkIntervalParam]; set || strings.Contains(startup.Parameters["options"], checkIntervalParam) {
		return
	}
	startup.Parameters[checkIntervalParam] = strconv.FormatInt(ms, 10)
}

// sameCertificate reports whether both sides use TLS and the server presented the proxy's own certificate, so channel binding works end to end.
func sameCertificate(client, server net.Conn, cfg *tls.Config) bool {
	_, clientTLS := client.(*tls.Conn)
	serverTLS, ok := server.(*tls.Conn)
	if !clientTLS || !ok || cfg == nil || len(cfg.Certificates) == 0 {
		return false
	}
	// The handshake proved the server holds the key for the certificate it sent, so a copied certificate can't pass.
	peer := serverTLS.ConnectionState().PeerCertificates
	return len(peer) > 0 && bytes.Equal(peer[0].Raw, cfg.Certificates[0].Certificate[0])
}
