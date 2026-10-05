package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Avik-creator/queryguard/internal/testcert"
	"github.com/Avik-creator/queryguard/pkg/plan"
	"github.com/Avik-creator/queryguard/pkg/policy"
	"github.com/Avik-creator/queryguard/pkg/wire"
	"github.com/jackc/pgx/v5/pgproto3"
)

func TestForwardsStartupToUpstream(t *testing.T) {
	pg := startFakePostgres(t)
	addr, _ := startProxy(t, newServer(t, pg.addr))

	startSession(t, addr)

	got := mustReceive[*pgproto3.StartupMessage](t, pg.received)
	if got.Parameters["user"] != "alice" || got.Parameters["database"] != "shop" {
		t.Errorf("upstream got %v; want user alice, database shop", got.Parameters)
	}
}

func TestAsksPostgresToNoticeClosedClients(t *testing.T) {
	for name, tc := range map[string]struct {
		interval time.Duration
		params   map[string]string
		want     string
	}{
		"added":                  {2 * time.Second, nil, "2000"},
		"client's value kept":    {2 * time.Second, map[string]string{checkIntervalParam: "500"}, "500"},
		"client's options kept":  {2 * time.Second, map[string]string{"options": "-c client_connection_check_interval=500"}, ""},
		"off when interval is 0": {0, nil, ""},
	} {
		t.Run(name, func(t *testing.T) {
			pg := startFakePostgres(t)
			s := newServer(t, pg.addr)
			s.ClientCheckInterval = tc.interval

			got := upstreamParams(t, s, pg, tc.params)

			if v := got[checkIntervalParam]; v != tc.want {
				t.Errorf("upstream got %s=%q; want %q", checkIntervalParam, v, tc.want)
			}
		})
	}
}

func TestAsksPostgresForTighterKeepalive(t *testing.T) {
	defaults := map[string]string{
		"tcp_keepalives_idle":     "15",
		"tcp_keepalives_interval": "5",
		"tcp_keepalives_count":    "3",
		"tcp_user_timeout":        "30000",
	}
	for name, tc := range map[string]struct {
		keepAlive net.KeepAliveConfig
		params    map[string]string
		want      map[string]string
	}{
		"added":               {DefaultKeepAlive, nil, defaults},
		"client's value kept": {DefaultKeepAlive, map[string]string{"tcp_keepalives_idle": "60"}, with(defaults, "tcp_keepalives_idle", "60")},
		"client's options kept": {DefaultKeepAlive, map[string]string{"options": "-c tcp_user_timeout=0"},
			with(defaults, "tcp_user_timeout", "")},
		"off when disabled": {net.KeepAliveConfig{}, nil, map[string]string{}},
	} {
		t.Run(name, func(t *testing.T) {
			pg := startFakePostgres(t)
			s := newServer(t, pg.addr)
			s.KeepAlive = tc.keepAlive

			got := upstreamParams(t, s, pg, tc.params)

			for param := range defaults {
				if got[param] != tc.want[param] {
					t.Errorf("upstream got %s=%q; want %q", param, got[param], tc.want[param])
				}
			}
		})
	}
}

func TestRelaysMessagesBothWays(t *testing.T) {
	pg := startFakePostgres(t)
	addr, _ := startProxy(t, newServer(t, pg.addr))
	conn := startSession(t, addr)

	roundTrip(t, conn, "hello")
}

func TestRejectsStatementsByPolicy(t *testing.T) {
	s := newServer(t, startFakePostgres(t).addr)
	s.Policy = mustPolicy(t, `{"rules": [{"check": "require_where"}]}`)
	addr, _ := startProxy(t, s)
	conn := startSession(t, addr)

	send(t, conn, &pgproto3.Query{String: "delete from orders"})

	if e, ok := receive(t, conn).(*pgproto3.ErrorResponse); !ok || e.Code != "42501" {
		t.Fatalf("got %#v; want error 42501", e)
	}
	if _, ok := receive(t, conn).(*pgproto3.ReadyForQuery); !ok {
		t.Fatal("no ReadyForQuery after the rejection")
	}
	roundTrip(t, conn, "select 1")
}

func TestCapsConnectionsPerTenant(t *testing.T) {
	s := newServer(t, startFakePostgres(t).addr)
	s.Policy = mustPolicy(t, `{"tenant_max_connections": 1, "tenants": {"bob": {"max_connections": 2}}}`)
	addr, _ := startProxy(t, s)
	first := startSession(t, addr)

	expectOverCap(t, sendStartupAs(t, dial(t, addr), "alice"))
	// bob has a cap of their own.
	loginAs(t, dial(t, addr), "bob")
	loginAs(t, dial(t, addr), "bob")
	expectOverCap(t, sendStartupAs(t, dial(t, addr), "bob"))

	first.Close()
	waitForSessionSlot(t, addr)
}

func TestCapsConnectionsInTotal(t *testing.T) {
	s := newServer(t, startFakePostgres(t).addr)
	s.Policy = mustPolicy(t, `{"max_connections": 1}`)
	addr, _ := startProxy(t, s)
	startSession(t, addr)

	expectOverCap(t, sendStartupAs(t, dial(t, addr), "bob"))
}

func TestCountsOnlyLoggedInSessions(t *testing.T) {
	pg := serveFakePostgres(t, &fakePostgres{greetingFor: map[string][]encoder{"stall": {&pgproto3.AuthenticationCleartextPassword{}}}})
	s := newServer(t, pg.addr)
	s.Policy = mustPolicy(t, `{"tenant_max_connections": 1}`)
	addr, _ := startProxy(t, s)

	// Anyone can claim to be alice; connections left at the password prompt must not take alice's slot.
	for range 3 {
		conn := dial(t, addr)
		send(t, conn, &pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersion30, Parameters: map[string]string{"user": "alice", "database": "stall"}})
		if msg := receive(t, conn); !isType[*pgproto3.AuthenticationCleartextPassword](msg) {
			t.Fatalf("got %#v; want a password prompt", msg)
		}
	}

	startSession(t, addr)
	expectOverCap(t, sendStartupAs(t, dial(t, addr), "alice"))
}

func TestRefusesLoginWithSearchPathOutsideAllowlist(t *testing.T) {
	pg := startFakePostgres(t)
	s := newServer(t, pg.addr)
	s.Policy = mustPolicy(t, `{"rules": [{"check": "schema_allowlist", "schemas": ["public"]}]}`)
	addr, _ := startProxy(t, s)

	conn := dial(t, addr)
	send(t, conn, &pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersion30, Parameters: map[string]string{"user": "alice", "options": "-c search_path=billing"}})

	expectFatal(t, conn, "42501")
	if len(pg.received) > 0 {
		t.Error("the refused login reached Postgres")
	}
	startSession(t, addr)
}

func TestChecksStatementsWithSettingsFromLogin(t *testing.T) {
	// With standard_conforming_strings off, Postgres ends the string at \' and runs the DELETE.
	const hidden = `select '\''; delete from orders; --'`
	for scs, wantRejected := range map[string]bool{"on": false, "off": true} {
		pg := serveFakePostgres(t, &fakePostgres{greeting: []encoder{
			&pgproto3.AuthenticationOk{},
			&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"},
			&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: scs},
			fakeServerKey,
			&pgproto3.ReadyForQuery{TxStatus: 'I'},
		}})
		s := newServer(t, pg.addr)
		s.Policy = mustPolicy(t, `{"rules": [{"check": "require_where"}]}`)
		addr, _ := startProxy(t, s)
		conn := startSession(t, addr)

		if !wantRejected {
			roundTrip(t, conn, hidden)
			continue
		}
		send(t, conn, &pgproto3.Query{String: hidden})
		if e, ok := receive(t, conn).(*pgproto3.ErrorResponse); !ok || e.Message != "queryguard: statement could not be checked" {
			t.Fatalf("standard_conforming_strings %s: got %#v; want the statement rejected unchecked", scs, e)
		}
	}
}

func TestLogsPlanCacheStats(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs bytes.Buffer
		s := &Server{Plans: plan.Cache{RefreshOneIn: -1}}
		tick := make(chan time.Time)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			s.logPlanStats(ctx, slog.New(slog.NewTextHandler(&logs, nil)), tick)
		}()
		explain := func() (plan.Plan, error) { time.Sleep(2 * time.Millisecond); return plan.Plan{}, nil }

		s.Plans.Get("a", explain)
		s.Plans.Get("a", explain)
		s.Plans.Get("a", explain)
		s.Plans.Get("b", explain)
		tick <- time.Now()
		// Nothing new since the last tick, so nothing is logged.
		tick <- time.Now()
		tick <- time.Now()
		cancel()
		<-done

		lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
		if len(lines) != 1 || !strings.Contains(lines[0], "hits=2 misses=2 hit_rate=0.5") || !strings.Contains(lines[0], "explain_avg=2ms") {
			t.Errorf("logged %q; want one line with 2 hits, 2 misses and 2ms per explain", logs.String())
		}
		if got := s.PlanStats(); got.Hits != 2 || got.Misses != 2 {
			t.Errorf("PlanStats = %+v; want 2 hits and 2 misses", got)
		}
	})
}

func TestReloadReachesOpenSessions(t *testing.T) {
	s := newServer(t, startFakePostgres(t).addr)
	s.Policy = mustPolicy(t, `{}`)
	addr, _ := startProxy(t, s)
	// The session opens under the first policy, which blocks nothing.
	conn := startSession(t, addr)

	s.SetPolicy(mustPolicy(t, `{"rules": [{"check": "require_where"}]}`))

	send(t, conn, &pgproto3.Query{String: "delete from orders"})
	if typ := receiveType(t, conn); typ != 'E' {
		t.Fatalf("got message %q after the reload; want the rejection", typ)
	}
	if s.ActivePolicy() == s.Policy {
		t.Error("ActivePolicy is still the first policy")
	}
}

func TestRulesMatchClientAddress(t *testing.T) {
	for clients, want := range map[string]bool{`["127.0.0.1"]`: true, `["10.0.0.0/8"]`: false} {
		s := newServer(t, startFakePostgres(t).addr)
		s.Policy = mustPolicy(t, `{"rules": [{"check": "require_where", "match": {"clients": `+clients+`}}]}`)
		addr, _ := startProxy(t, s)
		conn := startSession(t, addr)

		send(t, conn, &pgproto3.Query{String: "delete from orders"})

		// fakePostgres echoes what reaches it, so an allowed statement comes back as a Query.
		if blocked := receiveType(t, conn) == 'E'; blocked != want {
			t.Errorf("clients %s: blocked = %v; want %v", clients, blocked, want)
		}
	}
}

func TestCancelsStatementWhenClientLeaves(t *testing.T) {
	pg := startFakePostgres(t)
	addr, _ := startProxy(t, newServer(t, pg.addr))
	conn := startSession(t, addr)
	mustReceive[*pgproto3.StartupMessage](t, pg.received)
	// fakePostgres echoes the Query instead of answering it, so the statement never ends.
	send(t, conn, &pgproto3.Query{String: "select pg_sleep(60)"})
	receiveType(t, conn)

	conn.Close()

	expectServerKey(t, mustReceive[*pgproto3.CancelRequest](t, pg.received))
}

func TestCancelsStatementPastTenantTimeout(t *testing.T) {
	pg := startFakePostgres(t)
	s := newServer(t, pg.addr)
	s.Policy = mustPolicy(t, `{"tenant_defaults": {"statement_timeout": "100ms"}}`)
	addr, _ := startProxy(t, s)
	conn := startSession(t, addr)
	mustReceive[*pgproto3.StartupMessage](t, pg.received)

	send(t, conn, &pgproto3.Query{String: "select pg_sleep(60)"})

	expectServerKey(t, mustReceive[*pgproto3.CancelRequest](t, pg.received))
}

func TestGivesClientItsOwnCancelKey(t *testing.T) {
	addr, _ := startProxy(t, newServer(t, startFakePostgres(t).addr))

	key := login(t, dial(t, addr))

	if key.ProcessID == fakeServerKey.ProcessID || bytes.Equal(key.SecretKey, fakeServerKey.SecretKey) {
		t.Errorf("client got %+v; want key data other than the server's", key)
	}
	if len(key.SecretKey) != len(fakeServerKey.SecretKey) {
		t.Errorf("client got a %d-byte key; want %d bytes like the server's", len(key.SecretKey), len(fakeServerKey.SecretKey))
	}
}

func TestForwardsCancelRequestWithServerKey(t *testing.T) {
	pg := startFakePostgres(t)
	addr, _ := startProxy(t, newServer(t, pg.addr))
	key := login(t, dial(t, addr))
	conn := dial(t, addr)

	send(t, conn, &pgproto3.CancelRequest{ProcessID: key.ProcessID, SecretKey: key.SecretKey})

	mustReceive[*pgproto3.StartupMessage](t, pg.received)
	expectServerKey(t, mustReceive[*pgproto3.CancelRequest](t, pg.received))
	expectClosed(t, conn)
}

func TestIgnoresCancelRequestWithUnknownKey(t *testing.T) {
	pg := startFakePostgres(t)
	addr, _ := startProxy(t, newServer(t, pg.addr))
	conn := dial(t, addr)

	send(t, conn, &pgproto3.CancelRequest{ProcessID: fakeServerKey.ProcessID, SecretKey: fakeServerKey.SecretKey})

	expectClosed(t, conn)
	select {
	case msg := <-pg.received:
		t.Fatalf("upstream got %#v; want nothing", msg)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestRelaysOverDirectTLS(t *testing.T) {
	cert, clientTLS := testcert.Pair(t)
	s := newServer(t, startFakePostgres(t).addr)
	s.TLSConfig = wire.ServerTLSConfig(cert)
	addr, _ := startProxy(t, s)

	clientTLS.NextProtos = []string{"postgresql"}
	conn := tls.Client(dial(t, addr), clientTLS)
	login(t, conn)

	roundTrip(t, conn, "hello over TLS")
}

func TestForwardsCancelRequestOverTLS(t *testing.T) {
	cert, clientTLS := testcert.Pair(t)
	pg := startFakePostgres(t)
	s := newServer(t, pg.addr)
	s.TLSConfig = wire.ServerTLSConfig(cert)
	addr, _ := startProxy(t, s)
	key := login(t, dial(t, addr))

	raw := dial(t, addr)
	send(t, raw, &pgproto3.SSLRequest{})
	reply := make([]byte, 1)
	if _, err := io.ReadFull(raw, reply); err != nil || reply[0] != 'S' {
		t.Fatalf("got %q, %v; want 'S'", reply, err)
	}
	send(t, tls.Client(raw, clientTLS), &pgproto3.CancelRequest{ProcessID: key.ProcessID, SecretKey: key.SecretKey})

	mustReceive[*pgproto3.StartupMessage](t, pg.received)
	expectServerKey(t, mustReceive[*pgproto3.CancelRequest](t, pg.received))
}

func TestEndsTLSCancelConnectionWithCloseNotify(t *testing.T) {
	cert, clientTLS := testcert.Pair(t)
	s := newServer(t, startFakePostgres(t).addr)
	s.TLSConfig = wire.ServerTLSConfig(cert)
	// Without session tickets, the only bytes the proxy can send after the handshake are the close_notify alert.
	s.TLSConfig.SessionTicketsDisabled = true
	addr, _ := startProxy(t, s)
	key := login(t, dial(t, addr))

	raw := dial(t, addr)
	clientTLS.NextProtos = []string{"postgresql"}
	send(t, tls.Client(raw, clientTLS), &pgproto3.CancelRequest{ProcessID: key.ProcessID, SecretKey: key.SecretKey})

	// libpq's encrypted cancel reports "SSL error: unexpected eof" when the proxy just drops the connection.
	raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	if after, err := io.ReadAll(raw); len(after) == 0 {
		t.Fatalf("proxy closed the TLS cancel connection without close_notify (%v)", err)
	}
}

func TestPassesChannelBindingWhenProxyHasPostgresCertificate(t *testing.T) {
	cert, _ := testcert.Pair(t)

	got := offeredMechanisms(t, cert, cert, true)

	if !slices.Equal(got, []string{"SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"}) {
		t.Errorf("client was offered %q; want SCRAM-SHA-256-PLUS kept", got)
	}
}

func TestHidesChannelBindingWhenCertificatesDiffer(t *testing.T) {
	proxyCert, _ := testcert.Pair(t)
	pgCert, _ := testcert.Pair(t)

	got := offeredMechanisms(t, proxyCert, pgCert, true)

	if !slices.Equal(got, []string{"SCRAM-SHA-256"}) {
		t.Errorf("client was offered %q; want only SCRAM-SHA-256", got)
	}
}

func TestHidesChannelBindingFromPlaintextClient(t *testing.T) {
	cert, _ := testcert.Pair(t)

	got := offeredMechanisms(t, cert, cert, false)

	if !slices.Equal(got, []string{"SCRAM-SHA-256"}) {
		t.Errorf("client was offered %q; want only SCRAM-SHA-256", got)
	}
}

func TestStaysQuietWhenClientLeavesDuringLogin(t *testing.T) {
	pg := serveFakePostgres(t, &fakePostgres{greeting: []encoder{
		&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}},
	}})
	var logs bytes.Buffer
	s := newServer(t, pg.addr)
	s.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	addr, stop := startProxy(t, s)
	conn := dial(t, addr)
	sendStartup(t, conn)
	receive(t, conn)

	conn.Close()
	stop()

	if logs.Len() > 0 {
		t.Errorf("proxy logged %q; want nothing", logs.String())
	}
}

func TestEndsRefusedLoginQuietly(t *testing.T) {
	pg := serveFakePostgres(t, &fakePostgres{greeting: []encoder{
		&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "password authentication failed"},
	}})
	var logs bytes.Buffer
	s := newServer(t, pg.addr)
	s.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	addr, stop := startProxy(t, s)
	conn := dial(t, addr)
	sendStartup(t, conn)

	expectFatal(t, conn, "28P01")
	stop()

	// Postgres logs a failed login itself; it is no fault of the proxy.
	if logs.Len() > 0 {
		t.Errorf("proxy logged %q; want nothing", logs.String())
	}
}

func TestConnectsToUpstreamOverTLS(t *testing.T) {
	cert, clientTLS := testcert.Pair(t)
	pg := serveFakePostgres(t, &fakePostgres{tls: wire.ServerTLSConfig(cert)})
	s := newServer(t, pg.addr)
	s.Upstream = Dialer{Addr: pg.addr, TLSConfig: clientTLS}
	addr, _ := startProxy(t, s)

	conn := startSession(t, addr)

	roundTrip(t, conn, "hello")
}

func TestForwardsCancelRequestToUpstreamOverTLS(t *testing.T) {
	cert, clientTLS := testcert.Pair(t)
	pg := serveFakePostgres(t, &fakePostgres{tls: wire.ServerTLSConfig(cert)})
	s := newServer(t, pg.addr)
	s.Upstream = Dialer{Addr: pg.addr, TLSConfig: clientTLS}
	addr, _ := startProxy(t, s)
	key := login(t, dial(t, addr))

	send(t, dial(t, addr), &pgproto3.CancelRequest{ProcessID: key.ProcessID, SecretKey: key.SecretKey})

	mustReceive[*pgproto3.StartupMessage](t, pg.received)
	expectServerKey(t, mustReceive[*pgproto3.CancelRequest](t, pg.received))
}

func TestFailsWhenUpstreamRefusesTLS(t *testing.T) {
	_, clientTLS := testcert.Pair(t)
	pg := startFakePostgres(t)
	s := newServer(t, pg.addr)
	s.Upstream = Dialer{Addr: pg.addr, TLSConfig: clientTLS}
	addr, _ := startProxy(t, s)
	conn := dial(t, addr)

	sendStartup(t, conn)

	expectFatal(t, conn, "08006")
}

func TestFailsWhenUpstreamCertificateIsUntrusted(t *testing.T) {
	cert, _ := testcert.Pair(t)
	pg := serveFakePostgres(t, &fakePostgres{tls: wire.ServerTLSConfig(cert)})
	s := newServer(t, pg.addr)
	s.Upstream = Dialer{Addr: pg.addr, TLSConfig: &tls.Config{ServerName: "localhost"}}
	addr, _ := startProxy(t, s)
	conn := dial(t, addr)

	sendStartup(t, conn)

	expectFatal(t, conn, "08006")
}

func TestSendsFatalErrorWhenUpstreamUnreachable(t *testing.T) {
	// A port that was just released has nothing listening on it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := ln.Addr().String()
	ln.Close()

	addr, _ := startProxy(t, newServer(t, upstream))
	conn := dial(t, addr)
	sendStartup(t, conn)

	expectFatal(t, conn, "08006")
}

func TestClosesClientWhenUpstreamCloses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	addr, _ := startProxy(t, newServer(t, ln.Addr().String()))
	conn := dial(t, addr)
	sendStartup(t, conn)

	expectClosed(t, conn)
}

func TestClosesClientThatSendsNoStartup(t *testing.T) {
	s := newServer(t, startFakePostgres(t).addr)
	s.StartupTimeout = 100 * time.Millisecond
	addr, _ := startProxy(t, s)

	conn := dial(t, addr)

	expectClosed(t, conn)
}

func TestServeReturnsNilWhenStopped(t *testing.T) {
	_, stop := startProxy(t, newServer(t, startFakePostgres(t).addr))

	if err := stop(); err != nil {
		t.Fatalf("Serve returned %v; want nil", err)
	}
}

func TestShutdownWaitsForOpenSessions(t *testing.T) {
	s := newServer(t, startFakePostgres(t).addr)
	s.ShutdownTimeout = 5 * time.Second
	addr, stop := startProxy(t, s)
	conn := startSession(t, addr)
	roundTrip(t, conn, "before")

	done := make(chan error, 1)
	go func() { done <- stop() }()

	select {
	case <-done:
		t.Fatal("Serve returned while a session was still open")
	case <-time.After(200 * time.Millisecond):
	}
	if c, err := net.Dial("tcp", addr); err == nil {
		c.Close()
		t.Error("proxy accepted a new connection during shutdown")
	}
	roundTrip(t, conn, "during")

	conn.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v; want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after the last session ended")
	}
}

func TestShutdownClosesSessionsAfterTimeout(t *testing.T) {
	s := newServer(t, startFakePostgres(t).addr)
	s.ShutdownTimeout = 100 * time.Millisecond
	addr, stop := startProxy(t, s)
	conn := startSession(t, addr)
	roundTrip(t, conn, "hello")

	start := time.Now()
	if err := stop(); err != nil {
		t.Fatalf("Serve returned %v; want nil", err)
	}
	if elapsed := time.Since(start); elapsed < s.ShutdownTimeout {
		t.Errorf("Serve returned after %v; want at least the %v timeout", elapsed, s.ShutdownTimeout)
	}
	expectClosed(t, conn)
}

// newServer returns a Server for upstream that logs to the test output.
func newServer(t *testing.T, upstream string) *Server {
	return &Server{
		Upstream: Dialer{Addr: upstream},
		Logger:   slog.New(slog.NewTextHandler(t.Output(), nil)),
	}
}

// fakePostgres records each client's startup packet, sends its greeting, then echoes bytes back.
type fakePostgres struct {
	addr        string
	received    chan pgproto3.FrontendMessage
	tls         *tls.Config          // when set, plaintext connections are dropped
	greeting    []encoder            // sent after a startup message; a trust login with fakeServerKey when empty
	greetingFor map[string][]encoder // replaces greeting for logins to these databases
}

// fakeServerKey is the cancel key data fakePostgres gives every session.
var fakeServerKey = &pgproto3.BackendKeyData{ProcessID: 4242, SecretKey: bytes.Repeat([]byte{7}, 32)}

func startFakePostgres(t *testing.T) *fakePostgres { return serveFakePostgres(t, &fakePostgres{}) }

func serveFakePostgres(t *testing.T, pg *fakePostgres) *fakePostgres {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	pg.addr = ln.Addr().String()
	pg.received = make(chan pgproto3.FrontendMessage, 10)
	greeting := pg.greeting
	if len(greeting) == 0 {
		greeting = []encoder{&pgproto3.AuthenticationOk{}, fakeServerKey, &pgproto3.ReadyForQuery{TxStatus: 'I'}}
	}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				conn, msg, err := wire.Negotiate(raw, pg.tls)
				if err != nil {
					return
				}
				if _, ok := conn.(*tls.Conn); pg.tls != nil && !ok {
					return
				}
				pg.received <- msg
				startup, ok := msg.(*pgproto3.StartupMessage)
				if !ok {
					return
				}
				reply := greeting
				if g, ok := pg.greetingFor[startup.Parameters["database"]]; ok {
					reply = g
				}
				for _, m := range reply {
					buf, _ := m.Encode(nil)
					conn.Write(buf)
				}
				io.Copy(conn, conn)
			}()
		}
	}()
	return pg
}

// offeredMechanisms logs in through a proxy presenting proxyCert to a Postgres presenting pgCert that offers both SCRAM methods.
func offeredMechanisms(t *testing.T, proxyCert, pgCert tls.Certificate, clientTLS bool) []string {
	t.Helper()
	pg := serveFakePostgres(t, &fakePostgres{tls: wire.ServerTLSConfig(pgCert), greeting: []encoder{
		&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"}},
	}})
	s := newServer(t, pg.addr)
	s.TLSConfig = wire.ServerTLSConfig(proxyCert)
	// Certificate checks are tested elsewhere; here only the mechanism list matters.
	s.Upstream = Dialer{Addr: pg.addr, TLSConfig: &tls.Config{InsecureSkipVerify: true}}
	addr, _ := startProxy(t, s)

	conn := dial(t, addr)
	if clientTLS {
		conn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"postgresql"}})
	}
	sendStartup(t, conn)

	sasl, ok := receive(t, conn).(*pgproto3.AuthenticationSASL)
	if !ok {
		t.Fatalf("client got %#v; want AuthenticationSASL", sasl)
	}
	return sasl.AuthMechanisms
}

// upstreamParams logs in through s as alice with extra startup params and returns the params pg received.
func upstreamParams(t *testing.T, s *Server, pg *fakePostgres, extra map[string]string) map[string]string {
	t.Helper()
	addr, _ := startProxy(t, s)
	params := map[string]string{"user": "alice"}
	maps.Copy(params, extra)
	send(t, dial(t, addr), &pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersion30, Parameters: params})
	return mustReceive[*pgproto3.StartupMessage](t, pg.received).Parameters
}

func mustPolicy(t *testing.T, config string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(config))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// sendStartupAs sends a startup message for role and returns conn.
func sendStartupAs(t *testing.T, conn net.Conn, role string) net.Conn {
	t.Helper()
	send(t, conn, &pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersion30, Parameters: map[string]string{"user": role}})
	return conn
}

// waitForSessionSlot retries logging in as alice until the proxy has counted a closed session out.
func waitForSessionSlot(t *testing.T, addr string) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		conn := sendStartupAs(t, dial(t, addr), "alice")
		receive(t, conn)
		if !isType[*pgproto3.ErrorResponse](receive(t, conn)) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("closed session still counts against the cap after 2s")
		}
	}
}

// with returns a copy of m with key set to v; an empty v removes key.
func with(m map[string]string, key, v string) map[string]string {
	m = maps.Clone(m)
	m[key] = v
	if v == "" {
		delete(m, key)
	}
	return m
}

// startProxy runs s.Serve on a free port and returns its address and a stop function.
func startProxy(t *testing.T, s *Server) (addr string, stop func() error) {
	t.Helper()
	return startProxyOn(t, s, listen(t))
}

// listen opens a listener on a free local port.
func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

// startProxyOn runs s.Serve on ln and returns its address and a stop function.
func startProxyOn(t *testing.T, s *Server, ln net.Listener) (addr string, stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- s.Serve(ctx, ln) }()

	stopped := false
	stop = func() error {
		cancel()
		stopped = true
		return <-errc
	}
	t.Cleanup(func() {
		if !stopped {
			stop()
		}
	})
	return ln.Addr().String(), stop
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// startSession connects to the proxy and logs in.
func startSession(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn := dial(t, addr)
	login(t, conn)
	return conn
}

// login logs in as alice on conn, reads up to ReadyForQuery and returns the cancel key data the client got.
func login(t *testing.T, conn net.Conn) *pgproto3.BackendKeyData {
	t.Helper()
	sendStartup(t, conn)
	return finishLogin(t, conn)
}

// loginAs logs in as role on conn.
func loginAs(t *testing.T, conn net.Conn, role string) {
	t.Helper()
	sendStartupAs(t, conn, role)
	finishLogin(t, conn)
}

// finishLogin reads up to ReadyForQuery and returns the cancel key data the client got.
func finishLogin(t *testing.T, conn net.Conn) *pgproto3.BackendKeyData {
	t.Helper()
	var key *pgproto3.BackendKeyData
	for {
		switch msg := receive(t, conn).(type) {
		case *pgproto3.AuthenticationOk, *pgproto3.ParameterStatus:
		case *pgproto3.BackendKeyData:
			key = msg
		case *pgproto3.ReadyForQuery:
			if key == nil {
				t.Fatal("login ended without BackendKeyData")
			}
			return key
		default:
			t.Fatalf("got %#v during login", msg)
		}
	}
}

// expectServerKey fails the test unless req carries fakeServerKey.
func expectServerKey(t *testing.T, req *pgproto3.CancelRequest) {
	t.Helper()
	if req.ProcessID != fakeServerKey.ProcessID || !bytes.Equal(req.SecretKey, fakeServerKey.SecretKey) {
		t.Errorf("upstream got cancel %+v; want the server's own key data", req)
	}
}

// sendStartup sends a startup message for alice and the shop database.
func sendStartup(t *testing.T, conn net.Conn) {
	t.Helper()
	send(t, conn, &pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersion30,
		Parameters:      map[string]string{"user": "alice", "database": "shop"},
	})
}

type encoder interface{ Encode([]byte) ([]byte, error) }

func send(t *testing.T, conn net.Conn, msg encoder) {
	t.Helper()
	buf, err := msg.Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(buf); err != nil {
		t.Fatal(err)
	}
}

// receive reads exactly one server message from conn within 2s.
func receive(t *testing.T, conn net.Conn) pgproto3.BackendMessage {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	head := make([]byte, 5)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatalf("read message: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint32(head[1:])-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read message: %v", err)
	}
	msg, err := pgproto3.NewFrontend(bytes.NewReader(append(head, body...)), io.Discard).Receive()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// receiveType reads the next message on conn, whatever it is, and returns its type.
func receiveType(t *testing.T, conn net.Conn) byte {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	head := make([]byte, 5)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := io.CopyN(io.Discard, conn, int64(binary.BigEndian.Uint32(head[1:]))-4); err != nil {
		t.Fatalf("read: %v", err)
	}
	return head[0]
}

// expectOverCap fails the test unless conn logs in and is then refused as over a connection cap, as Postgres refuses.
func expectOverCap(t *testing.T, conn net.Conn) {
	t.Helper()
	if msg := receive(t, conn); !isType[*pgproto3.AuthenticationOk](msg) {
		t.Fatalf("got %#v; want AuthenticationOk", msg)
	}
	expectFatal(t, conn, "53300")
}

func isType[T any](v any) bool {
	_, ok := v.(T)
	return ok
}

// expectFatal fails the test unless conn gets a FATAL error with code and is then closed.
func expectFatal(t *testing.T, conn net.Conn, code string) {
	t.Helper()
	msg := receive(t, conn)
	if e, ok := msg.(*pgproto3.ErrorResponse); !ok || e.Severity != "FATAL" || e.Code != code {
		t.Fatalf("got %#v; want FATAL %s", msg, code)
	}
	expectClosed(t, conn)
}

// mustReceive waits up to 2s for the next message on ch and checks its type.
func mustReceive[T pgproto3.FrontendMessage](t *testing.T, ch <-chan pgproto3.FrontendMessage) T {
	t.Helper()
	select {
	case msg := <-ch:
		got, ok := msg.(T)
		if !ok {
			t.Fatalf("upstream got %T; want %T", msg, *new(T))
		}
		return got
	case <-time.After(2 * time.Second):
		t.Fatalf("upstream got nothing in 2s; want %T", *new(T))
		panic("unreachable")
	}
}

// roundTrip sends msg as a Query through conn and checks fakePostgres's echo comes back.
func roundTrip(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	want, _ := (&pgproto3.Query{String: msg}).Encode(nil)
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	defer conn.SetDeadline(time.Time{})
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q back; want %q", got, want)
	}
}

// expectClosed fails the test unless the proxy closes conn within 2s.
func expectClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := conn.Read(make([]byte, 1))
	switch {
	case err == nil:
		t.Fatal("read succeeded; want the proxy to close the connection")
	case errors.Is(err, os.ErrDeadlineExceeded):
		t.Fatal("connection still open after 2s; want the proxy to close it")
	}
}
