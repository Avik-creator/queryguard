// Package proxy relays each client connection to its own upstream Postgres connection.
package proxy

import (
	"cmp"
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// DefaultShutdownTimeout is used when Server.ShutdownTimeout is zero.
const DefaultShutdownTimeout = 30 * time.Second

// Server relays client connections to Upstream, one server connection per client.
type Server struct {
	Upstream        string        // host:port of the Postgres server
	ShutdownTimeout time.Duration // how long sessions may drain after Serve stops
	Logger          *slog.Logger  // nil means slog.Default()
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
		sessions.Go(func() { s.relay(sessionCtx, log, client) })
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

// relay copies bytes between client and a new upstream connection until either side closes.
func (s *Server) relay(ctx context.Context, log *slog.Logger, client net.Conn) {
	defer client.Close()

	var d net.Dialer
	server, err := d.DialContext(ctx, "tcp", s.Upstream)
	if err != nil {
		log.Error("connect to upstream", "upstream", s.Upstream, "client", client.RemoteAddr(), "err", err)
		return
	}
	defer server.Close()

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
		io.Copy(client, server)
		closeBoth()
	})
	copies.Wait()
}
