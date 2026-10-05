// Package proxy relays each client connection to its own upstream Postgres connection.
package proxy

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"maps"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Avik-creator/queryguard/internal/safe"
	"github.com/Avik-creator/queryguard/pkg/fleet"
	"github.com/Avik-creator/queryguard/pkg/plan"
	"github.com/Avik-creator/queryguard/pkg/policy"
	"github.com/Avik-creator/queryguard/pkg/sched"
	"github.com/Avik-creator/queryguard/pkg/session"
	"github.com/Avik-creator/queryguard/pkg/stats"
	"github.com/Avik-creator/queryguard/pkg/telemetry"
	"github.com/Avik-creator/queryguard/pkg/wire"
	"github.com/jackc/pgx/v5/pgproto3"
)

// Defaults used when the matching Server field is zero.
const (
	DefaultStartupTimeout  = 10 * time.Second
	DefaultShutdownTimeout = 30 * time.Second
)

// DefaultMaxStartups is the suggested MaxStartups: it keeps file descriptors free for sessions and their upstream connections.
const DefaultMaxStartups = 1000

// Backoff after a failed Accept, as net/http does: running out of file descriptors passes once sessions end.
const (
	minAcceptDelay = 5 * time.Millisecond
	maxAcceptDelay = time.Second
)

// DefaultClientCheckInterval is the suggested ClientCheckInterval; zero there means off.
const DefaultClientCheckInterval = 2 * time.Second

// cancelTimeout bounds sending a CancelRequest for a session.
const cancelTimeout = 5 * time.Second

// planStatsInterval is how often the plan cache's hit rate and explain time are logged.
const planStatsInterval = time.Minute

// checkIntervalParam makes Postgres poll the socket during a query and stop it once the connection is closed.
const checkIntervalParam = "client_connection_check_interval"

// Server relays client connections to Upstream, one server connection per client.
type Server struct {
	Upstream  Upstream
	TLSConfig *tls.Config // nil means clients are told TLS is unavailable
	// RequireClientTLS refuses a login without TLS, which hostssl in pg_hba.conf can't do since Postgres sees only the proxy.
	RequireClientTLS bool
	StartupTimeout   time.Duration // how long a new client has to send its startup message, and the upstream to take the connection
	ShutdownTimeout  time.Duration // how long sessions may drain after Serve stops
	MaxStartups      int           // connections at once that have yet to send their startup message; 0 means DefaultMaxStartups
	Logger           *slog.Logger  // nil means slog.Default()

	// ClientCheckInterval is sent as client_connection_check_interval unless the client set it; 0 sends nothing.
	ClientCheckInterval time.Duration
	// KeepAlive is set on client sockets and sent to Postgres for its side; a disabled config leaves both alone.
	KeepAlive net.KeepAliveConfig
	// Policy is the policy the server starts with: rules, tenants, budgets and caps; nil checks nothing. SetPolicy replaces it.
	Policy *policy.Policy
	// Catalog gives the cost rules table sizes; nil leaves every size unknown.
	Catalog *plan.Catalog
	// Monitor reports what the whole server is doing, such as lock waits, every second; nil reads nothing.
	Monitor Monitor
	// Fleet shares budgets and slots with the other instances in front of the same server; nil keeps them to this instance.
	Fleet *fleet.Fleet
	// Plans caches statement plans for every session's cost rules.
	Plans plan.Cache
	// History learns how each statement's plans run, for calibrated costs and plan flips.
	History plan.History
	// Stats gathers each statement's calls, time, rows and errors by fingerprint and tenant; nil gathers none.
	Stats *stats.Table
	// Runaways are the statements recently cancelled for breaking their timeout or a cap.
	Runaways policy.Watch
	// Kills are the tenants and statements blocked from the admin console.
	Kills policy.Kills
	// Allowlist holds each role's learned statements, for the allowlist in the config.
	Allowlist policy.Allowlist
	// AdminDatabase is the database name that opens the admin console instead of a session; "" turns the console off.
	AdminDatabase string
	// AdminAuthDatabase is the real database a console login is checked against; "" means DefaultAdminAuthDatabase.
	AdminAuthDatabase string
	// Reload reads the config file again, for the console's RELOAD; nil means there is none.
	Reload func() error
	// Metrics gets the proxy's metrics, such as statements by tenant and open sessions; nil keeps none.
	Metrics *telemetry.Registry

	keys     cancelKeys
	sessions sessionCount
	throttle loginThrottle
	backends backends
	policies policy.Holder
	open     atomic.Int64  // sessions connected to Postgres
	starting atomic.Int64  // connections that have yet to send their startup message
	capacity atomic.Uint64 // the server's measured cost units a second, as float64 bits; 0 until measured

	// Each holds back a flood of one kind of line, such as failed handshakes from a port scanner.
	startupLogs, cancelLogs quietLog

	// Only the Monitor's goroutine uses these.
	observed   time.Time              // when it last reported
	lagging    bool                   // a standby lags, so best-effort statements are held
	horizonPID int32                  // the backend whose snapshot is past max_age, or 0
	deadBase   map[plan.Table]float64 // the watched tables' dead tuples when that snapshot passed max_age
	capped     string                 // the tenant limited to one statement at a time for holding that snapshot, or ""

	// fleetMu guards these, which say what the Fleet asks for.
	fleetMu   sync.Mutex
	known     map[string]time.Time // tenants with the default budget seen lately, when last seen
	lastWants time.Time

	// Made from Metrics by Serve; nil without it.
	statements *telemetry.Counter
	took       *telemetry.Histogram

	mu      sync.Mutex
	sched   *sched.Scheduler // made with the first policy and reconfigured by each one after
	serving context.Context  // Serve's context, which ends the scheduler's loop; nil before Serve
}

// Monitor reports what the whole server is doing; *plan.Monitor reads it from Postgres.
type Monitor interface {
	Run(ctx context.Context, report func(plan.Activity))
}

// Listen listens on addr; with reusePort, other processes may listen on it too, so a new one can take connections while an old one drains.
func Listen(ctx context.Context, addr string, reusePort bool) (net.Listener, error) {
	var lc net.ListenConfig
	if reusePort {
		lc.Control = func(_, _ string, raw syscall.RawConn) error {
			var err error
			if cerr := raw.Control(func(fd uintptr) { err = setReusePort(fd) }); cerr != nil {
				return cerr
			}
			return err
		}
	}
	return lc.Listen(ctx, "tcp", addr)
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

	if s.Policy != nil && s.policies.Load() == nil {
		s.SetPolicy(s.Policy)
	}
	if s.Metrics != nil {
		s.registerMetrics(s.Metrics)
	}
	s.mu.Lock()
	s.serving = ctx
	if s.sched != nil {
		go safe.Loop(ctx, log, "scheduler", s.sched.Run)
	}
	s.mu.Unlock()
	if s.Monitor != nil {
		go safe.Loop(ctx, log, "monitor", func(ctx context.Context) { s.Monitor.Run(ctx, s.observe) })
	}
	if s.Fleet != nil {
		// Sessions get the instance's ID in their cancel keys, which it has only once the store answered, so accepting waits a little.
		first := make(chan struct{})
		renewed := sync.OnceFunc(func() { close(first) })
		go safe.Loop(ctx, log, "fleet", func(ctx context.Context) {
			s.Fleet.Run(ctx, s.fleetWants, func() {
				s.applyFleet()
				renewed()
			})
		})
		select {
		case <-first:
		case <-time.After(fleetStartWait):
		case <-ctx.Done():
		}
		// Its leases go only once its sessions have ended, since until then they may use them.
		defer func() {
			rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cancelTimeout)
			defer cancel()
			if err := s.Fleet.Release(rctx); err != nil {
				log.Warn("release fleet leases", "err", err)
			}
		}()
	}
	if s.Stats != nil {
		if s.Stats.Tenant == nil {
			s.Stats.Tenant = s.tenantOf
		}
		if s.Stats.Units == nil {
			s.Stats.Units = s.History.CostOf
		}
		go safe.Loop(ctx, log, "stats", s.Stats.Run)
		go safe.Loop(ctx, log, "anomalies", func(ctx context.Context) {
			tick := time.Tick(time.Minute)
			for {
				select {
				case <-ctx.Done():
					return
				case now := <-tick:
					logAnomalies(log, s.Stats.Minute(now))
				}
			}
		})
	}
	go safe.Loop(ctx, log, "capacity", func(ctx context.Context) {
		tick := time.Tick(capacityInterval)
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick:
				s.applyCapacity()
			}
		}
	})
	if s.ActivePolicy() != nil {
		tick := time.Tick(planStatsInterval)
		go safe.Loop(ctx, log, "plan stats", func(ctx context.Context) { s.logPlanStats(ctx, log, tick) })
	}

	var sessions sync.WaitGroup
	var delay time.Duration
	for {
		client, err := ln.Accept()
		if err != nil && ctx.Err() == nil && temporary(err) {
			delay = min(max(2*delay, minAcceptDelay), maxAcceptDelay)
			log.Warn("accept failed; retrying", "err", err, "retry_in", delay)
			select {
			case <-ctx.Done():
			case <-time.After(delay):
			}
			continue
		}
		if err != nil {
			if ctx.Err() == nil {
				// The listener failed on its own, not because we stopped it.
				closeSessions()
				sessions.Wait()
				return err
			}
			break
		}
		delay = 0
		// handle gives the slot back once the startup message is in.
		if s.starting.Add(1) > int64(cmp.Or(s.MaxStartups, DefaultMaxStartups)) {
			s.starting.Add(-1)
			if ok, held := s.startupLogs.allow(time.Now()); ok {
				log.Warn("closed connection over the cap on connections starting up", heldBack(held, "client", client.RemoteAddr())...)
			}
			client.Close()
			continue
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
	// A bug in one session ends that session, not every client's; the other defers still give back its slots and keys.
	defer safe.Recover(func(err error) { logPanic(log, client, err) })
	defer client.Close()
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()
	if err := setKeepAlive(client, s.KeepAlive); err != nil {
		log.Warn("set keepalive on client connection", "client", client.RemoteAddr(), "err", err)
	}

	// The deadline covers the TLS handshake too, since the TLS connection reads through client.
	client.SetDeadline(time.Now().Add(cmp.Or(s.StartupTimeout, DefaultStartupTimeout)))
	conn, msg, err := wire.Negotiate(client, s.TLSConfig)
	s.starting.Add(-1)
	if err != nil {
		// A client that connects and leaves without a word, like a TCP health check, is not an error.
		if !errors.Is(err, io.EOF) {
			if ok, held := s.startupLogs.allow(time.Now()); ok {
				log.Warn("client startup failed", heldBack(held, "client", client.RemoteAddr(), "err", err)...)
			}
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
			if forwarded, err := s.forwardCancel(ctx, msg); forwarded {
				if err != nil {
					if ok, held := s.cancelLogs.allow(time.Now()); ok {
						log.Warn("forward cancel request to its instance", heldBack(held, "client", client.RemoteAddr(), "err", err)...)
					}
				}
				return
			}
			if ok, held := s.cancelLogs.allow(time.Now()); ok {
				log.Info("ignored cancel request with unknown key", heldBack(held, "client", client.RemoteAddr())...)
			}
			return
		}
		if err := s.Upstream.Cancel(ctx, req); err != nil {
			if ok, held := s.cancelLogs.allow(time.Now()); ok {
				log.Warn("forward cancel request", heldBack(held, "client", client.RemoteAddr(), "err", err)...)
			}
		}
	case *pgproto3.StartupMessage:
		if _, encrypted := conn.(*tls.Conn); s.RequireClientTLS && !encrypted {
			wire.SendFatal(conn, "28000", "queryguard requires TLS: connect with sslmode=require or stronger")
			return
		}
		s.relay(ctx, log, conn, msg)
	}
}

// relay connects client to an upstream connection and relays messages both ways until either side closes.
func (s *Server) relay(ctx context.Context, log *slog.Logger, client net.Conn, startup *pgproto3.StartupMessage) {
	role := pgName(startup.Parameters["user"])
	// Postgres connects a client that names no database to the one named after its role.
	database := pgName(cmp.Or(startup.Parameters["database"], role))
	throttle, key := s.loginThrottle(), throttleKey{clientAddr(client), role}
	if wait := s.throttle.coolingOff(key, time.Now()); wait > 0 && throttle.Failures > 0 {
		wire.SendFatal(client, "28000", fmt.Sprintf("queryguard: too many failed logins; retry in about %s", wait.Round(time.Second)))
		return
	}
	if s.AdminDatabase != "" && database == s.AdminDatabase {
		s.admin(ctx, log, client, startup, role, key, throttle)
		return
	}
	var (
		check         session.Checker
		authenticated func() *wire.Error
		release       = func() {}
		running       *backend // what the server connection runs, for the checks that read the server's activity
	)
	if p := s.ActivePolicy(); p != nil {
		c := s.policies.Checker(role, log.With("client", client.RemoteAddr()))
		c.Env = policy.Env{Database: database, Client: clientAddr(client), Plans: &s.Plans, History: &s.History, Scheduler: s.scheduler(),
			Runaways: &s.Runaways, Kills: &s.Kills, Allowlist: &s.Allowlist}
		if s.Catalog != nil {
			c.Env.Tables = s.Catalog
		}
		if s.Stats != nil {
			c.Env.WAL, c.Env.P99, c.Env.Flipped = s.Stats.WALPerCall, s.Stats.P99, s.Stats.Flipped
		}
		if s.Monitor != nil {
			running = &backend{}
			c.Env.Backend = running
		}
		if rej := c.CheckStartup(wire.StartupSettings(startup.Parameters)); rej != nil {
			if buf, err := rej.Encode(nil); err == nil {
				client.Write(buf)
			}
			return
		}
		check = c
		total, tenant := p.ConnectionLimits(role)
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
	capped := authenticated
	authenticated = func() *wire.Error {
		s.throttle.succeeded(key)
		if capped != nil {
			return capped()
		}
		return nil
	}

	s.addSettings(startup)
	// A server that takes the connection and never answers would otherwise hold the session forever.
	actx, connected := context.WithTimeout(ctx, cmp.Or(s.StartupTimeout, DefaultStartupTimeout))
	server, err := s.Upstream.Acquire(actx, startup)
	connected()
	if err != nil {
		log.Error("connect to upstream", "client", client.RemoteAddr(), "err", err)
		wire.SendFatal(client, "08006", "queryguard: cannot connect to the database server")
		return
	}
	defer s.Upstream.Release(server)
	s.open.Add(1)
	defer s.open.Add(-1)

	// The login sets forget and unfile; they are called once the session is over.
	forget, unfile := func() {}, func() {}
	var serverKey atomic.Pointer[pgproto3.BackendKeyData]
	opts := wire.StartupOptions{
		ChannelBinding: sameCertificate(client, server, s.TLSConfig),
		Authenticated:  authenticated,
		IssueKey: func(key *pgproto3.BackendKeyData) *pgproto3.BackendKeyData {
			serverKey.Store(key)
			forget()
			issued, f := s.keys.issue(key, s.fleetID())
			forget = f
			if running != nil {
				unfile()
				unfile = s.backends.add(int32(key.ProcessID), running)
			}
			return issued
		},
	}
	stop := context.AfterFunc(ctx, func() {
		client.Close()
		server.Close()
	})
	defer stop()

	// The session cancels a statement past its timeout or left behind by its client, with the server's own key.
	cancel := func() {
		key := serverKey.Load()
		if key == nil {
			return
		}
		cctx, done := context.WithTimeout(context.WithoutCancel(ctx), cancelTimeout)
		defer done()
		if err := s.Upstream.Cancel(cctx, &pgproto3.CancelRequest{ProcessID: key.ProcessID, SecretKey: key.SecretKey}); err != nil {
			log.Warn("cancel statement", "client", client.RemoteAddr(), "err", err)
		}
	}
	var record func(session.Finished)
	if t := s.Stats; t != nil || s.statements != nil {
		record = func(f session.Finished) {
			if t != nil {
				t.Record(stats.Statement{At: time.Now(), Database: database, Role: role, SQL: f.SQL, Took: f.Took, Rows: f.Rows, Code: f.Code,
					Message: f.Message, Rejected: f.Rejected, NotRun: f.NotRun})
			}
			s.count(role, f)
		}
	}
	err = session.Relay(client, server, session.Options{Check: check, Cancel: cancel, Record: record, Drain: s.draining(),
		Interrupt: func(interrupt func(session.Interruption) bool) {
			if running != nil {
				running.setInterrupt(interrupt)
			}
		},
		Login: func(client io.Writer, server io.Reader, report func(name, value string)) error {
			opts.Report = report
			return wire.RelayStartup(client, server, opts)
		}})
	forget()
	unfile()
	// A wrong password and a pg_hba.conf rejection count; a server that is starting up or full doesn't.
	if e, ok := errors.AsType[*wire.LoginRefusedError](err); ok && (e.Code == "28P01" || e.Code == "28000") && throttle.Failures > 0 {
		if s.throttle.failed(key, time.Now(), throttle) {
			log.Warn("refusing logins after repeated failures", "client", client.RemoteAddr(), "role", role,
				"failures", throttle.Failures, "cool_off", time.Duration(throttle.CoolOff))
		}
	}
	// A login refused over the cap was logged when it was refused, and Postgres logs the logins it refuses.
	switch _, refused := errors.AsType[*wire.Error](err); {
	case isPanic(err):
		logPanic(log, client, err)
	case !refused && !errors.Is(err, wire.ErrLoginRefused) && !errors.Is(err, session.ErrDrained) && !hungUp(err):
		log.Warn("session ended", "client", client.RemoteAddr(), "err", err)
	}
}

// loginThrottle returns the login throttle of the policy in force, or the default one without a policy.
func (s *Server) loginThrottle() policy.LoginThrottle {
	if p := s.ActivePolicy(); p != nil {
		return p.LoginThrottle()
	}
	return (&policy.Policy{}).LoginThrottle()
}

// logAnomalies logs each anomaly a minute started or ended.
func logAnomalies(log *slog.Logger, anomalies []stats.Anomaly) {
	for _, a := range anomalies {
		if a.Ended {
			log.Info("anomaly ended", "signal", a.Signal, "value", a.Value, "baseline", a.Baseline)
			continue
		}
		log.Warn("anomaly", "signal", a.Signal, "value", a.Value, "baseline", a.Baseline, "statements", a.Statements, "flips", a.Flips,
			"lock_waits", a.LockWaits)
	}
}

// tenantOf returns the tenant role's statement sql runs for under the policy in force.
func (s *Server) tenantOf(role, sql string) string {
	if p := s.ActivePolicy(); p != nil {
		return p.TenantOf(role, sql)
	}
	return role
}

// isPanic reports whether err is a recovered panic.
func isPanic(err error) bool {
	_, ok := errors.AsType[*safe.Panic](err)
	return ok
}

// logPanic logs the panic that ended client's session, with its stack.
func logPanic(log *slog.Logger, client net.Conn, err error) {
	p, _ := errors.AsType[*safe.Panic](err)
	log.Error("session panicked", "client", client.RemoteAddr(), "panic", p.Value, "stack", string(p.Stack))
}

// temporary reports whether a failed Accept may work if tried again, as after running out of file descriptors.
func temporary(err error) bool {
	errno, ok := errors.AsType[syscall.Errno](err)
	return ok && errno.Temporary()
}

// maxNameLen is NAMEDATALEN-1, the longest role or database name in a default Postgres build.
const maxNameLen = 63

// pgName cuts a name from a startup packet to maxNameLen bytes, as Postgres does before looking it up, even mid-character.
func pgName(name string) string { return name[:min(len(name), maxNameLen)] }

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

// A quietLog lets quietBurst lines through in each quietWindow.
const (
	quietBurst  = 10
	quietWindow = time.Minute
)

// quietLog holds back a flood of one kind of log line and counts the lines it held back.
type quietLog struct {
	mu    sync.Mutex
	start time.Time // when the current window began
	n     int       // lines let through in it
	held  int       // lines held back since the last one let through
}

// allow reports whether a line may be logged at now, and how many were held back before it.
func (q *quietLog) allow(now time.Time) (bool, int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if now.Sub(q.start) >= quietWindow {
		q.start, q.n = now, 0
	}
	if q.n >= quietBurst {
		q.held++
		return false, 0
	}
	q.n++
	held := q.held
	q.held = 0
	return true, held
}

// heldBack returns attrs, with the number of lines held back before this one when there were any.
func heldBack(held int, attrs ...any) []any {
	if held > 0 {
		attrs = append(attrs, "lines_held_back", held)
	}
	return attrs
}

// sameCertificate reports whether both sides use TLS and the server presented the proxy's own certificate, so channel binding works end to end.
func sameCertificate(client, server net.Conn, cfg *tls.Config) bool {
	_, clientTLS := client.(*tls.Conn)
	serverTLS, ok := server.(*tls.Conn)
	if !clientTLS || !ok || cfg == nil {
		return false
	}
	own := ownCertificate(cfg)
	// The handshake proved the server holds the key for the certificate it sent, so a copied certificate can't pass.
	peer := serverTLS.ConnectionState().PeerCertificates
	return own != nil && len(peer) > 0 && bytes.Equal(peer[0].Raw, own.Certificate[0])
}

// ownCertificate returns the certificate cfg offers clients now, which GetCertificate may change on a reload, or nil.
func ownCertificate(cfg *tls.Config) *tls.Certificate {
	if cfg.GetCertificate != nil {
		if cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{}); err == nil && cert != nil && len(cert.Certificate) > 0 {
			return cert
		}
		return nil
	}
	if len(cfg.Certificates) == 0 || len(cfg.Certificates[0].Certificate) == 0 {
		return nil
	}
	return &cfg.Certificates[0]
}

// durationBuckets are the statement time histogram's upper bounds, in seconds.
var durationBuckets = []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}

// registerMetrics adds the proxy's metrics to r.
func (s *Server) registerMetrics(r *telemetry.Registry) {
	s.statements = r.Counter("queryguard_statements_total", "Statements by tenant and result: ok, error, rejected by QueryGuard, or not_run when Parse or Bind failed.", "tenant", "result")
	s.took = r.Histogram("queryguard_statement_duration_seconds", "Time from sending a statement to Postgres to its answer, by tenant.", durationBuckets, "tenant")
	r.Gauge("queryguard_sessions", "Client sessions connected to Postgres.", func(emit func(float64, ...string)) { emit(float64(s.open.Load())) })
	r.Gauge("queryguard_connections_starting", "Connections yet to send their startup message.", func(emit func(float64, ...string)) {
		emit(float64(s.starting.Load()))
	})
	r.Gauge("queryguard_capacity_units_per_second", "The server's measured cost units a second; 0 until measured.", func(emit func(float64, ...string)) {
		emit(math.Float64frombits(s.capacity.Load()))
	})
	r.Gauge("queryguard_admission_limit", "Statements the fast lane runs at once now, as the adaptive limit sets it; 0 means no limit.",
		func(emit func(float64, ...string)) {
			if sc := s.scheduler(); sc != nil {
				emit(float64(sc.Limit()))
			}
		})
	tenants := func(value func(sched.TenantState) float64) func(func(float64, ...string)) {
		return func(emit func(float64, ...string)) {
			if sc := s.scheduler(); sc != nil {
				for _, t := range sc.Tenants() {
					emit(value(t), t.Name)
				}
			}
		}
	}
	r.Gauge("queryguard_tenant_running", "Statements each tenant runs now.", tenants(func(t sched.TenantState) float64 { return float64(t.Running) }), "tenant")
	r.Gauge("queryguard_tenant_budget_units", "Cost units each tenant has left; below zero, what it owes.", tenants(func(t sched.TenantState) float64 { return t.Tokens }), "tenant")
	r.CounterFunc("queryguard_plan_cache_hits_total", "Statements whose plan came from the cache.", func(emit func(float64, ...string)) {
		emit(float64(s.Plans.Stats().Hits))
	})
	r.CounterFunc("queryguard_plan_cache_misses_total", "Statements QueryGuard explained.", func(emit func(float64, ...string)) {
		emit(float64(s.Plans.Stats().Misses))
	})
	r.CounterFunc("queryguard_explain_seconds_total", "Time spent explaining statements, which is what the cost check adds to queries.",
		func(emit func(float64, ...string)) { emit(s.Plans.Stats().Explaining.Seconds()) })
}

// count adds a finished statement of role to the metrics.
func (s *Server) count(role string, f session.Finished) {
	if s.statements == nil {
		return
	}
	tenant := s.tenantOf(role, f.SQL)
	result := "ok"
	switch {
	case f.Rejected:
		result = "rejected"
	case f.NotRun:
		result = "not_run"
	case f.Code != "":
		result = "error"
	}
	s.statements.Inc(tenant, result)
	if f.Took > 0 && !f.Rejected {
		s.took.Observe(f.Took.Seconds(), tenant)
	}
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
		now := s.Plans.Stats()
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

// maxObserveGap caps the time one reading accounts for, so readings missed while the catalog was unreachable aren't charged.
const maxObserveGap = 5 * time.Second

// lockTimeout is what a client gets when the DDL guard cancels its statement: Postgres's own lock_timeout error, which migration tools retry.
var lockTimeout = session.Interruption{Code: "55P03", Message: "queryguard: canceling statement due to lock timeout",
	Hint: "QueryGuard cancels DDL that waits on a lock while other statements queue behind it, or longer than ddl_guard's lock_timeout. " +
		"Retry when the table is less busy."}

// observe acts on one reading of the server's activity.
func (s *Server) observe(a plan.Activity) {
	if s.Stats != nil {
		if a.Statements != nil {
			s.Stats.Counters(a.Statements)
		}
		s.Stats.LockWaits(a.LockWaits())
	}
	now := time.Now()
	elapsed := min(now.Sub(s.observed), maxObserveGap)
	if s.observed.IsZero() {
		elapsed = 0
	}
	s.observed = now

	sc, p := s.scheduler(), s.ActivePolicy()
	if sc != nil {
		sc.LockWaits(a.LockWaits())
	}
	// A session others wait on is let past the limits, since only its next statement can end their wait.
	blocking := map[int32]bool{}
	for _, w := range a.Waiting {
		for _, pid := range w.Blockers {
			blocking[pid] = true
		}
	}
	for pid, b := range s.backends.all() {
		b.setBlocking(blocking[pid])
	}
	if p == nil {
		return
	}
	s.guardDDL(p, a, blocking)
	if sc == nil {
		return
	}
	if p.BlockerPays() && elapsed > 0 {
		s.chargeBlockers(sc, a, elapsed)
	}
	s.watchLag(sc, p, a)
	s.watchHorizon(sc, p, a)
}

// watchLag holds best-effort statements while a standby lags more than the policy allows.
func (s *Server) watchLag(sc *sched.Scheduler, p *policy.Policy, a plan.Activity) {
	limit := p.ReplicationLag()
	lagging := limit > 0 && a.ReplicationLag > limit
	if lagging == s.lagging {
		return
	}
	s.lagging = lagging
	sc.HoldBestEffort(lagging)
	log := cmp.Or(s.Logger, slog.Default())
	if lagging {
		log.Warn("holding best-effort statements while a standby lags", "rule", "replication_lag", "lag", a.ReplicationLag, "max", limit)
	} else {
		log.Info("standbys caught up; best-effort statements run again", "rule", "replication_lag", "lag", a.ReplicationLag)
	}
}

// watchHorizon limits to one statement at a time the tenant whose old snapshot holds back the MVCC horizon while the watched tables bloat.
func (s *Server) watchHorizon(sc *sched.Scheduler, p *policy.Policy, a plan.Activity) {
	h := p.Horizon()
	var tenant string
	if h.MaxAge > 0 && a.Horizon.PID != 0 && a.Horizon.Age > time.Duration(h.MaxAge) {
		if a.Horizon.PID != s.horizonPID {
			s.horizonPID, s.deadBase = a.Horizon.PID, maps.Clone(a.DeadTuples)
		}
		if b := s.backends.get(a.Horizon.PID); b != nil && (len(h.Watch) == 0 || grown(s.deadBase, a.DeadTuples) > h.MaxDeadTuples) {
			tenant, _ = b.state()
		}
	} else {
		s.horizonPID, s.deadBase = 0, nil
	}
	if tenant == s.capped {
		return
	}
	log := cmp.Or(s.Logger, slog.Default())
	if s.capped != "" {
		sc.CapTenant(s.capped, 0)
		log.Info("MVCC horizon moved on; tenant runs freely again", "rule", "mvcc_horizon", "tenant", s.capped)
	}
	s.capped = tenant
	if tenant == "" {
		return
	}
	attrs := []any{"rule", "mvcc_horizon", "tenant", tenant, "pid", a.Horizon.PID, "snapshot_age", a.Horizon.Age}
	if p.TenantMode(tenant) == policy.Warn {
		log.Warn("would limit tenant holding back the MVCC horizon to one statement at a time", attrs...)
		return
	}
	sc.CapTenant(tenant, 1)
	log.Warn("limiting tenant holding back the MVCC horizon to one statement at a time", attrs...)
}

// grown returns the most any table's dead tuples grew from base to now.
func grown(base, now map[plan.Table]float64) float64 {
	var most float64
	for t, n := range now {
		most = max(most, n-base[t])
	}
	return most
}

// guardDDL cancels this proxy's DDL that waits on a lock while others queue behind it, or past the guard's lock_timeout.
func (s *Server) guardDDL(p *policy.Policy, a plan.Activity, blocking map[int32]bool) {
	g := p.DDLGuard()
	if g.Mode == "off" {
		return
	}
	// A backend that others wait for while it waits itself is at the head of a lock queue.
	log := cmp.Or(s.Logger, slog.Default())
	for pid, w := range a.Waiting {
		b := s.backends.get(pid)
		if b == nil {
			continue
		}
		tenant, ddl := b.state()
		if !ddl || (!blocking[pid] && w.Waited < time.Duration(g.LockTimeout)) || !b.flag() {
			continue
		}
		attrs := []any{"rule", "ddl_guard", "tenant", tenant, "pid", pid, "waited", w.Waited, "queued_behind", blocking[pid]}
		if g.Mode == policy.Warn || p.TenantMode(tenant) == policy.Warn {
			log.Warn("would cancel DDL waiting on a lock", attrs...)
			continue
		}
		if b.cancel(lockTimeout) {
			log.Warn("cancelled DDL waiting on a lock", attrs...)
		}
	}
}

// chargeBlockers moves the cost of elapsed time spent waiting on a lock from each waiting tenant to the tenants it waits for.
func (s *Server) chargeBlockers(sc *sched.Scheduler, a plan.Activity, elapsed time.Duration) {
	cost, ok := s.History.CostOf(elapsed)
	if !ok {
		return
	}
	for pid, w := range a.Waiting {
		waiter := s.backends.get(pid)
		if waiter == nil || len(w.Blockers) == 0 {
			continue
		}
		waiting, _ := waiter.state()
		// The wait is shared among everyone it waits for, though only this proxy's sessions can be charged.
		share := cost / float64(len(w.Blockers))
		for _, blocker := range w.Blockers {
			if h := s.backends.get(blocker); h != nil {
				holding, _ := h.state()
				sc.Transfer(waiting, holding, share)
			}
		}
	}
}

// PlanStats returns what the plan cache has done since the server started.
func (s *Server) PlanStats() plan.Stats { return s.Plans.Stats() }

// SetPolicy puts p in force for new and open sessions alike, keeping each tenant's budget and use.
func (s *Server) SetPolicy(p *policy.Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sched == nil {
		s.sched = sched.New(s.schedConfig(p))
		if s.serving != nil {
			go safe.Loop(s.serving, cmp.Or(s.Logger, slog.Default()), "scheduler", s.sched.Run)
		}
	} else {
		s.sched.Configure(s.schedConfig(p))
	}
	s.policies.Store(p)
}

// draining returns a channel closed once Serve stops accepting, when sessions are to end as soon as they are idle.
func (s *Server) draining() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.serving == nil {
		return nil
	}
	return s.serving.Done()
}

// ActivePolicy returns the policy in force.
func (s *Server) ActivePolicy() *policy.Policy {
	if p := s.policies.Load(); p != nil {
		return p
	}
	return s.Policy
}

func (s *Server) scheduler() *sched.Scheduler {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sched
}

// fleetStartWait bounds how long Serve waits for the fleet's first lease before accepting.
const fleetStartWait = 2 * time.Second

// forgetTenantAfter is how long a tenant with the default budget goes without a statement before its share is no longer leased.
const forgetTenantAfter = 5 * time.Minute

// fleetID returns this instance's ID in the fleet, or 0.
func (s *Server) fleetID() int {
	if s.Fleet == nil {
		return 0
	}
	return s.Fleet.ID()
}

// forwardCancel sends a cancel request with a key this instance didn't issue to the instance that did, reporting whether it
// knew of one.
func (s *Server) forwardCancel(ctx context.Context, req *pgproto3.CancelRequest) (bool, error) {
	id := owner(req.ProcessID)
	if s.Fleet == nil || id == 0 || id == s.Fleet.ID() {
		return false, nil
	}
	addr, ok := s.Fleet.Peer(id)
	if !ok {
		return false, nil
	}
	dctx, cancel := context.WithTimeout(ctx, cancelTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		return true, err
	}
	defer conn.Close()
	return true, writeMessage(conn, req)
}

// fleetWants returns what this instance asks the fleet for: each budget's rate and each lane's slots, with what was used of them.
func (s *Server) fleetWants() map[string]fleet.Want {
	p, sc := s.ActivePolicy(), s.scheduler()
	if p == nil || sc == nil {
		return nil
	}
	cfg := s.byCapacity(p)
	d := sc.TakeDemand()
	wants := map[string]fleet.Want{}
	for _, l := range []struct {
		resource string
		lane     sched.Lane
		id       sched.LaneID
	}{{"slots:fast", cfg.Fast, sched.Fast}, {"slots:slow", cfg.Slow, sched.Slow}} {
		if l.lane.MaxActive > 0 {
			wants[l.resource] = fleet.Want{Capacity: float64(l.lane.MaxActive), Demand: float64(d.Slots[l.id]),
				Using: float64(d.Running[l.id]), Whole: true}
		}
	}

	s.fleetMu.Lock()
	defer s.fleetMu.Unlock()
	now := time.Now()
	elapsed := now.Sub(s.lastWants)
	if s.lastWants.IsZero() {
		elapsed = fleet.DefaultInterval
	}
	s.lastWants = now
	if s.known == nil {
		s.known = map[string]time.Time{}
	}
	for _, tenants := range []iter.Seq[string]{maps.Keys(d.Spent), maps.Keys(d.Starved)} {
		for t := range tenants {
			if _, listed := cfg.Budgets[t]; !listed && cfg.Default.Rate > 0 {
				s.known[t] = now
			}
		}
	}
	maps.DeleteFunc(s.known, func(_ string, seen time.Time) bool { return now.Sub(seen) > forgetTenantAfter })
	budget := func(tenant string, b sched.Budget) {
		demand := d.Spent[tenant] / elapsed.Seconds()
		// A tenant held back by its share would use more, so it asks for twice what it has, and with none, for the fallback share.
		if d.Starved[tenant] {
			demand = max(demand, 2*s.Fleet.Share("rate:"+tenant), b.Rate/float64(cmp.Or(s.Fleet.MaxInstances, fleet.DefaultMaxInstances)))
		}
		wants["rate:"+tenant] = fleet.Want{Capacity: b.Rate, Demand: demand}
	}
	for t, b := range cfg.Budgets {
		if b.Rate > 0 {
			budget(t, b)
		}
	}
	for t := range s.known {
		budget(t, cfg.Default)
	}
	return wants
}

// applyFleet puts the instance's new shares in force.
func (s *Server) applyFleet() {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Read under mu, which SetPolicy holds, so a reload can't be undone by the policy it replaced.
	if p := s.ActivePolicy(); s.sched != nil && p != nil {
		s.sched.Configure(s.schedConfig(p))
	}
}

// schedConfig is p's scheduler config with budgets by capacity turned into rates and every rate scaled to this instance's lease.
func (s *Server) schedConfig(p *policy.Policy) sched.Config {
	return s.scaled(s.byCapacity(p))
}

// byCapacity is p's scheduler config with budgets by capacity turned into rates, fleet-wide.
func (s *Server) byCapacity(p *policy.Policy) sched.Config {
	cfg := p.SchedConfig()
	capacity := math.Float64frombits(s.capacity.Load())
	byCapacity := func(b sched.Budget) sched.Budget {
		// Until statements have been timed the capacity isn't known, and the budget doesn't limit.
		if b.Capacity > 0 && capacity > 0 {
			b.Rate = b.Capacity * capacity
		}
		return b
	}
	for t, b := range cfg.Budgets {
		cfg.Budgets[t] = byCapacity(b)
	}
	cfg.Default = byCapacity(cfg.Default)
	return cfg
}

// capacityInterval is how often the server's capacity is measured for budgets by capacity.
const capacityInterval = 10 * time.Second

// capacityChange is how far the measured capacity must move before budgets by capacity are set again.
const capacityChange = 0.1

// applyCapacity measures the server's capacity, max_active statements at its time per cost unit, and sets budgets by capacity from it.
func (s *Server) applyCapacity() {
	p := s.ActivePolicy()
	perSecond, ok := s.History.CostOf(time.Second)
	if p == nil || !ok {
		return
	}
	capacity := float64(p.SchedConfig().Fast.MaxActive) * perSecond
	if old := math.Float64frombits(s.capacity.Load()); old > 0 && math.Abs(capacity-old) <= capacityChange*old {
		return
	}
	s.capacity.Store(math.Float64bits(capacity))
	s.mu.Lock()
	defer s.mu.Unlock()
	// Read again under mu, which SetPolicy holds, so a reload can't be undone by the policy it replaced.
	if p := s.ActivePolicy(); s.sched != nil && p != nil {
		s.sched.Configure(s.schedConfig(p))
	}
}

// scaled returns cfg with each fleet-wide limit cut to this instance's share, and shut where it has none, as before its first lease.
func (s *Server) scaled(cfg sched.Config) sched.Config {
	if s.Fleet == nil {
		return cfg
	}
	scale := func(tenant string, b sched.Budget) sched.Budget {
		if b.Rate <= 0 {
			return b
		}
		share := s.Fleet.Share("rate:" + tenant)
		if share <= 0 {
			b.Rate, b.Burst = -1, 0
			return b
		}
		b.Burst, b.Rate = cmp.Or(b.Burst, b.Rate)*share/b.Rate, share
		return b
	}
	budgets := map[string]sched.Budget{}
	for t, b := range cfg.Budgets {
		budgets[t] = scale(t, b)
	}
	s.fleetMu.Lock()
	for t := range s.known {
		if _, listed := budgets[t]; !listed {
			budgets[t] = scale(t, cfg.Default)
		}
	}
	s.fleetMu.Unlock()
	cfg.Budgets = budgets
	// A tenant not yet leased waits for its share, which the next lease brings.
	if cfg.Default.Rate > 0 {
		cfg.Default.Rate, cfg.Default.Burst = -1, 0
	}
	slots := func(resource string, n int) int {
		if n <= 0 {
			return n
		}
		if share := int(s.Fleet.Share(resource)); share > 0 {
			return share
		}
		return -1
	}
	cfg.Fast.MaxActive = slots("slots:fast", cfg.Fast.MaxActive)
	cfg.Slow.MaxActive = slots("slots:slow", cfg.Slow.MaxActive)
	return cfg
}

// clientAddr returns the client's IP address, or the zero Addr when it has none.
func clientAddr(conn net.Conn) netip.Addr {
	ap, _ := netip.ParseAddrPort(conn.RemoteAddr().String())
	return ap.Addr()
}
