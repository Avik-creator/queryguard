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
	"maps"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Avik-creator/queryguard/pkg/plan"
	"github.com/Avik-creator/queryguard/pkg/policy"
	"github.com/Avik-creator/queryguard/pkg/session"
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

// planStatsInterval is how often the plan cache's hit rate and explain time are logged.
const planStatsInterval = time.Minute

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
	// KeepAlive is set on client sockets and sent to Postgres for its side; a disabled config leaves both alone.
	KeepAlive net.KeepAliveConfig
	// Policy holds the statement rules and connection caps; nil checks nothing.
	Policy *policy.Policy
	// Catalog gives the cost rules table sizes; nil leaves every size unknown.
	Catalog *plan.Catalog

	keys     cancelKeys
	sessions sessionCount
	plans    plan.Cache
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

	if s.Policy != nil {
		go s.logPlanStats(ctx, log, time.Tick(planStatsInterval))
	}

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
	if err := setKeepAlive(client, s.KeepAlive); err != nil {
		log.Warn("set keepalive on client connection", "client", client.RemoteAddr(), "err", err)
	}

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
	// Closing a TLS conn sends close_notify first; libpq's encrypted cancel reports an error without it.
	defer conn.Close()

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

// relay connects client to an upstream connection and relays messages both ways until either side closes.
func (s *Server) relay(ctx context.Context, log *slog.Logger, client net.Conn, startup *pgproto3.StartupMessage) {
	role := startup.Parameters["user"]
	var (
		check         session.Checker
		authenticated func() *wire.Error
		release       = func() {}
	)
	if s.Policy != nil {
		c := s.Policy.Checker(role, log.With("client", client.RemoteAddr()))
		if rej := c.CheckStartup(wire.StartupSettings(startup.Parameters)); rej != nil {
			if buf, err := rej.Encode(nil); err == nil {
				client.Write(buf)
			}
			return
		}
		// Postgres connects a client that names no database to the one named after its role.
		c.Costs = policy.Costs{Database: cmp.Or(startup.Parameters["database"], role), Plans: &s.plans}
		if s.Catalog != nil {
			c.Costs.Tables = s.Catalog
		}
		check = c
		total, tenant := s.Policy.ConnectionLimits(role)
		// Like Postgres, count a session only once it has logged in, so a client without the password can't use up a role's cap.
		authenticated = func() *wire.Error {
			r, ok := s.sessions.add(role, total, tenant)
			if !ok {
				log.Warn("refused connection over the cap", "client", client.RemoteAddr(), "role", role)
				return &wire.Error{Code: "53300", Message: "queryguard: too many connections"}
			}
			release = r
			return nil
		}
	}
	// Relay has returned, and with it the login that set release, by the time this runs.
	defer func() { release() }()

	s.addSettings(startup)
	server, err := s.Upstream.Acquire(ctx, startup)
	if err != nil {
		log.Error("connect to upstream", "client", client.RemoteAddr(), "err", err)
		wire.SendFatal(client, "08006", "queryguard: cannot connect to the database server")
		return
	}
	defer s.Upstream.Release(server)

	// The login sets forget; it is called once the session is over.
	forget := func() {}
	opts := wire.StartupOptions{
		ChannelBinding: sameCertificate(client, server, s.TLSConfig),
		Authenticated:  authenticated,
		IssueKey: func(key *pgproto3.BackendKeyData) *pgproto3.BackendKeyData {
			forget()
			issued, f := s.keys.issue(key)
			forget = f
			return issued
		},
	}
	stop := context.AfterFunc(ctx, func() {
		client.Close()
		server.Close()
	})
	defer stop()

	err = session.Relay(client, server, check, func(client io.Writer, server io.Reader, report func(name, value string)) error {
		opts.Report = report
		return wire.RelayStartup(client, server, opts)
	})
	forget()
	// A login refused over the cap was logged when it was refused.
	if _, refused := errors.AsType[*wire.Error](err); !refused && !hungUp(err) {
		log.Warn("session ended", "client", client.RemoteAddr(), "err", err)
	}
}

// hungUp reports whether err only says that one side closed the connection, which is how every session ends.
func hungUp(err error) bool {
	// psql hangs up mid-login before every password prompt.
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET)
}

// addSettings adds the proxy's Postgres settings to startup, keeping any the client set directly or in options.
func (s *Server) addSettings(startup *pgproto3.StartupMessage) {
	settings := map[string]string{}
	maps.Copy(settings, keepAliveSettings(s.KeepAlive))
	if ms := s.ClientCheckInterval.Milliseconds(); ms > 0 {
		settings[checkIntervalParam] = strconv.FormatInt(ms, 10)
	}
	for name, value := range settings {
		// A startup parameter beats the same setting in options, so ours would silently replace the client's.
		if _, set := startup.Parameters[name]; set || strings.Contains(startup.Parameters["options"], name) {
			continue
		}
		startup.Parameters[name] = value
	}
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

// logPlanStats logs at each tick the cache hit rate and average explain time, the latency the cost check adds, since the last line.
func (s *Server) logPlanStats(ctx context.Context, log *slog.Logger, tick <-chan time.Time) {
	var last plan.Stats
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
		now := s.plans.Stats()
		hits, misses := now.Hits-last.Hits, now.Misses-last.Misses
		if hits+misses == 0 {
			continue
		}
		attrs := []any{"hits", hits, "misses", misses, "hit_rate", float64(hits) / float64(hits+misses)}
		if misses > 0 {
			attrs = append(attrs, "explain_avg", (now.Explaining-last.Explaining)/time.Duration(misses), "explain_slowest", now.Slowest)
		}
		log.Info("plan cache", attrs...)
		last = now
	}
}

// PlanStats returns what the plan cache has done since the server started.
func (s *Server) PlanStats() plan.Stats { return s.plans.Stats() }
