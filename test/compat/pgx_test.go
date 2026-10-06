// Package compat runs real clients against a real Postgres through QueryGuard; set QG_TEST_UPSTREAM to run it.
package compat

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Avik-creator/queryguard/internal/testcert"
	"github.com/Avik-creator/queryguard/pkg/proxy"
	"github.com/Avik-creator/queryguard/pkg/wire"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

func TestPgxConnects(t *testing.T) {
	qg := startProxy(t)
	for name, tc := range map[string]struct {
		opts    string
		wantTLS bool
	}{
		"plaintext":    {"sslmode=disable", false},
		"SSLRequest":   {"sslmode=verify-full sslrootcert=" + qg.caFile, true},
		"direct TLS":   {"sslmode=verify-full sslnegotiation=direct sslrootcert=" + qg.caFile, true},
		"protocol 3.2": {"sslmode=disable max_protocol_version=3.2", false},
		"3.2 over TLS": {"sslmode=verify-full sslrootcert=" + qg.caFile + " max_protocol_version=3.2", true},
	} {
		t.Run(name, func(t *testing.T) {
			conn := qg.connect(t, tc.opts)

			var one int
			if err := conn.QueryRow(t.Context(), "select 1").Scan(&one); err != nil || one != 1 {
				t.Fatalf("select 1 = %d, %v", one, err)
			}
			if _, isTLS := conn.PgConn().Conn().(*tls.Conn); isTLS != tc.wantTLS {
				t.Errorf("TLS to the proxy = %v; want %v", isTLS, tc.wantTLS)
			}
		})
	}
}

func TestPgxExtendedProtocol(t *testing.T) {
	conn := startProxy(t).connect(t, "sslmode=disable")

	// The second run reuses the statement pgx prepared and cached on the first.
	for range 2 {
		var sum int
		if err := conn.QueryRow(t.Context(), "select $1::int + $2::int", 2, 3).Scan(&sum); err != nil || sum != 5 {
			t.Fatalf("2 + 3 = %d, %v", sum, err)
		}
	}
}

func TestPgxCopy(t *testing.T) {
	conn := startProxy(t).connect(t, "sslmode=disable")
	ctx := t.Context()
	if _, err := conn.Exec(ctx, "create temp table qg_copy (id int, name text)"); err != nil {
		t.Fatal(err)
	}

	var in strings.Builder
	for i := range 1000 {
		fmt.Fprintf(&in, "%d,name %d\n", i, i)
	}
	tag, err := conn.PgConn().CopyFrom(ctx, strings.NewReader(in.String()), "copy qg_copy from stdin (format csv)")
	if err != nil || tag.RowsAffected() != 1000 {
		t.Fatalf("COPY FROM: %v rows, %v", tag.RowsAffected(), err)
	}

	var out strings.Builder
	if _, err := conn.PgConn().CopyTo(ctx, &out, "copy (select * from qg_copy order by id) to stdout (format csv)"); err != nil {
		t.Fatal(err)
	}
	if out.String() != in.String() {
		t.Errorf("COPY TO returned %d bytes; want the %d bytes copied in", out.Len(), in.Len())
	}
}

func TestPgxCancel(t *testing.T) {
	qg := startProxy(t)
	for name, opts := range map[string]string{
		"protocol 3.0":        "sslmode=disable",
		"protocol 3.2":        "sslmode=disable max_protocol_version=3.2",
		"protocol 3.2 on TLS": "sslmode=verify-full sslrootcert=" + qg.caFile + " max_protocol_version=3.2",
	} {
		t.Run(name, func(t *testing.T) {
			conn := qg.connect(t, opts)
			ctx := t.Context()

			var realPID uint32
			if err := conn.QueryRow(ctx, "select pg_backend_pid()").Scan(&realPID); err != nil {
				t.Fatal(err)
			}
			if conn.PgConn().PID() == realPID {
				t.Errorf("client was given the real backend pid %d", realPID)
			}

			time.AfterFunc(300*time.Millisecond, func() { conn.PgConn().CancelRequest(t.Context()) })
			start := time.Now()
			// A cancel that never arrives fails here after 10s rather than after the whole sleep.
			sleepCtx, stop := context.WithTimeout(ctx, 10*time.Second)
			defer stop()
			_, err := conn.Exec(sleepCtx, "select pg_sleep(30)")

			pgErr, ok := errors.AsType[*pgconn.PgError](err)
			if !ok || pgErr.Code != "57014" {
				t.Fatalf("pg_sleep(30) ended with %v; want SQLSTATE 57014", err)
			}
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Errorf("cancel took %v", elapsed)
			}
		})
	}
}

func TestPostgresStopsQueryWhenClientVanishes(t *testing.T) {
	qg := startProxy(t)
	app := fmt.Sprintf("qg_orphan_%d", time.Now().UnixNano())
	victim := qg.connect(t, "sslmode=disable application_name="+app)
	watcher := qg.connect(t, "sslmode=disable")

	running := make(chan struct{})
	go func() {
		defer close(running)
		victim.Exec(t.Context(), "select count(*) from generate_series(1, 3000000000)")
	}()
	waitFor(t, 5*time.Second, func() bool { return activeQueries(t, watcher, app) == 1 })

	// Closing the socket without a Terminate message looks to the proxy like a client that died.
	victim.PgConn().Conn().Close()
	<-running

	start := time.Now()
	waitFor(t, 10*time.Second, func() bool { return activeQueries(t, watcher, app) == 0 })
	t.Logf("Postgres stopped the query %v after the client vanished", time.Since(start).Round(100*time.Millisecond))
}

func TestPostgresUsesProxyKeepalive(t *testing.T) {
	conn := startProxy(t).connect(t, "sslmode=disable")

	got := map[string]string{}
	var name, setting string
	rows, _ := conn.Query(t.Context(), `select name, setting from pg_settings where name like 'tcp\_%' and source = 'client'`)
	if _, err := pgx.ForEachRow(rows, []any{&name, &setting}, func() error {
		got[name] = setting
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"tcp_keepalives_idle":     "15",
		"tcp_keepalives_interval": "5",
		"tcp_keepalives_count":    "3",
	}
	if !maps.Equal(got, want) {
		t.Errorf("session settings from the client are %v; want %v", got, want)
	}
}

// activeQueries counts running queries from sessions named app.
func activeQueries(t *testing.T, conn *pgx.Conn, app string) int {
	t.Helper()
	var n int
	err := conn.QueryRow(t.Context(), "select count(*) from pg_stat_activity where application_name = $1 and state = 'active'", app).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// waitFor polls cond every 100ms until it holds or timeout passes.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(timeout); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %v", timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// queryGuard is an in-process proxy in front of QG_TEST_UPSTREAM.
type queryGuard struct {
	addr   string
	caFile string // PEM that verifies the proxy's certificate for localhost
}

func startProxy(t testing.TB) *queryGuard {
	t.Helper()
	return startProxyWith(t, func(*proxy.Server) {})
}

// startProxyWith starts a proxy as startProxy does, letting configure change the server first.
func startProxyWith(t testing.TB, configure func(*proxy.Server)) *queryGuard {
	t.Helper()
	if os.Getenv("QG_TEST_UPSTREAM") == "" {
		t.Skip("set QG_TEST_UPSTREAM to a Postgres host:port, for example 127.0.0.1:5418 after make up")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	qg, _ := startProxyOn(t, ln, configure)
	return qg
}

// startProxyOn starts a proxy as startProxyWith does, on ln; stop starts its shutdown and waits for Serve to return.
func startProxyOn(t testing.TB, ln net.Listener, configure func(*proxy.Server)) (_ *queryGuard, stop func()) {
	t.Helper()
	upstream := os.Getenv("QG_TEST_UPSTREAM")
	if upstream == "" {
		t.Skip("set QG_TEST_UPSTREAM to a Postgres host:port, for example 127.0.0.1:5418 after make up")
	}
	cert, _ := testcert.Pair(t)
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &proxy.Server{
		Upstream:            proxy.Dialer{Addr: upstream, KeepAlive: proxy.DefaultKeepAlive},
		TLSConfig:           wire.ServerTLSConfig(cert),
		ClientCheckInterval: proxy.DefaultClientCheckInterval,
		KeepAlive:           proxy.DefaultKeepAlive,
		Logger:              slog.New(slog.NewTextHandler(t.Output(), nil)),
	}
	configure(s)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	stop = sync.OnceFunc(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	t.Cleanup(stop)
	return &queryGuard{addr: ln.Addr().String(), caFile: caFile}, stop
}

// connect opens a pgx connection through the proxy as the docker compose superuser, with extra connection options.
func (qg *queryGuard) connect(t testing.TB, opts string) *pgx.Conn {
	t.Helper()
	return connectTo(t, qg.addr, opts)
}

// connectTo opens a pgx connection to addr; verify-full connections use the name localhost so the test certificate matches.
func connectTo(t testing.TB, addr, opts string) *pgx.Conn {
	t.Helper()
	host, port, _ := net.SplitHostPort(addr)
	if strings.Contains(opts, "verify-full") {
		host = "localhost"
	}
	dsn := fmt.Sprintf("host=%s port=%s user=postgres password=%s dbname=queryguard connect_timeout=5 %s", host, port, password(), opts)
	conn, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

// password is the docker compose superuser's password.
func password() string { return cmp.Or(os.Getenv("PGPASSWORD"), "queryguard") }

func TestRollingRestartDropsNoBusySession(t *testing.T) {
	ln, err := proxy.Listen(t.Context(), "127.0.0.1:0", true)
	if err != nil {
		t.Fatal(err)
	}
	old, stopOld := startProxyOn(t, ln, func(s *proxy.Server) { s.ShutdownTimeout = 10 * time.Second })

	var committed, dropped, reconnects atomic.Int64
	ctx, stopLoad := context.WithCancel(t.Context())
	var load sync.WaitGroup
	for range 8 {
		load.Go(func() {
			var conn *pgx.Conn
			for ctx.Err() == nil {
				if conn == nil {
					c, err := pgx.Connect(ctx, fmt.Sprintf("host=127.0.0.1 port=%s user=postgres password=%s dbname=queryguard", port(old), password()))
					if err != nil {
						continue
					}
					conn = c
				}
				// A drained session is closed only between transactions, so only BEGIN may fail.
				if _, err := conn.Exec(ctx, "begin"); err != nil {
					conn.Close(context.Background())
					conn = nil
					reconnects.Add(1)
					continue
				}
				_, err1 := conn.Exec(ctx, "select pg_sleep(0.05)")
				_, err2 := conn.Exec(ctx, "select count(*) from customers where id < 100")
				_, err3 := conn.Exec(ctx, "commit")
				if err := cmp.Or(err1, err2, err3); err != nil {
					if ctx.Err() == nil {
						dropped.Add(1)
						t.Errorf("a transaction failed midway: %v", err)
					}
					conn.Close(context.Background())
					conn = nil
					continue
				}
				committed.Add(1)
			}
			if conn != nil {
				conn.Close(context.Background())
			}
		})
	}

	time.Sleep(time.Second)
	newLn, err := proxy.Listen(t.Context(), old.addr, true)
	if err != nil {
		t.Fatal(err)
	}
	startProxyOn(t, newLn, func(*proxy.Server) {})
	before := committed.Load()
	start := time.Now()
	stopOld()
	drained := time.Since(start)
	time.Sleep(2 * time.Second)
	stopLoad()
	load.Wait()

	if drained > 5*time.Second {
		t.Errorf("the old process took %v to drain; want its sessions ended as each transaction did", drained)
	}
	if after := committed.Load() - before; after == 0 {
		t.Error("no transaction committed through the new process")
	}
	t.Logf("committed %d, reconnected %d, dropped mid-transaction %d; old process drained in %v", committed.Load(), reconnects.Load(), dropped.Load(), drained)
}

func TestChannelBindingWithTLSOnBothSides(t *testing.T) {
	upstreamTLS := func(s *proxy.Server) {
		s.Upstream = proxy.Dialer{Addr: os.Getenv("QG_TEST_UPSTREAM"), TLSConfig: &tls.Config{InsecureSkipVerify: true}, KeepAlive: proxy.DefaultKeepAlive}
	}
	qg := startProxyWith(t, upstreamTLS)
	for opts, wantErr := range map[string]string{
		"sslmode=disable":                         "",
		"sslmode=require channel_binding=disable": "",
		// libpq and pgx send SCRAM's "y" flag over TLS when offered no -PLUS, which Postgres over TLS refuses.
		"sslmode=require channel_binding=prefer":  "channel_binding=disable",
		"sslmode=require channel_binding=require": "SCRAM-SHA-256-PLUS",
	} {
		conn, err := pgx.Connect(t.Context(), fmt.Sprintf("host=127.0.0.1 port=%s user=postgres password=%s dbname=queryguard %s", port(qg), password(), opts))
		if err == nil {
			conn.Close(context.Background())
		}
		var hint string
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
			hint = pgErr.Hint
		}
		switch {
		case wantErr == "" && err != nil:
			t.Errorf("%s: %v", opts, err)
		case wantErr != "" && (err == nil || !strings.Contains(err.Error()+hint, wantErr)):
			t.Errorf("%s: got %v (hint %q); want an error mentioning %q", opts, err, hint, wantErr)
		}
	}

	// With Postgres's own certificate the proxy passes -PLUS through, and binding holds end to end.
	cert, key := postgresCertificate(t)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	same := startProxyWith(t, func(s *proxy.Server) {
		upstreamTLS(s)
		s.TLSConfig = wire.ServerTLSConfig(pair)
	})
	conn, err := pgx.Connect(t.Context(), fmt.Sprintf("host=127.0.0.1 port=%s user=postgres password=%s dbname=queryguard sslmode=require channel_binding=require", port(same), password()))
	if err != nil {
		t.Fatalf("channel_binding=require through a proxy with Postgres's certificate: %v", err)
	}
	conn.Close(context.Background())
}

// postgresCertificate reads the test server's certificate and key out of its container, skipping the test without docker.
func postgresCertificate(t *testing.T) (cert, key []byte) {
	t.Helper()
	service := "pg" + port(&queryGuard{addr: os.Getenv("QG_TEST_UPSTREAM")})[2:]
	read := func(path string) []byte {
		out, err := exec.Command("docker", "compose", "exec", "-T", service, "cat", path).Output()
		if err != nil {
			t.Skipf("read %s from %s: %v", path, service, err)
		}
		return out
	}
	return read("/etc/ssl/certs/ssl-cert-snakeoil.pem"), read("/etc/ssl/private/ssl-cert-snakeoil.key")
}

func TestOAuthBearerLogsInThroughTheProxy(t *testing.T) {
	qg := startProxy(t)
	direct := connectTo(t, os.Getenv("QG_TEST_UPSTREAM"), "sslmode=disable")
	var oauth bool
	if err := direct.QueryRow(t.Context(), "select count(*) > 0 from pg_hba_file_rules where auth_method = 'oauth'").Scan(&oauth); err != nil || !oauth {
		t.Skipf("the upstream has no oauth line in pg_hba.conf (%v); it needs the pg18 image built from testdata/oauth", err)
	}
	if _, err := direct.Exec(t.Context(), "do $$ begin create role qg_oauth login; exception when duplicate_object then null; end $$"); err != nil {
		t.Fatal(err)
	}

	for token, wantOK := range map[string]bool{"queryguard-test-token": true, "a-stolen-token": false} {
		conn, err := net.Dial("tcp", qg.addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		fe := pgproto3.NewFrontend(conn, conn)
		receive := func() pgproto3.BackendMessage {
			t.Helper()
			msg, err := fe.Receive()
			if err != nil {
				t.Fatalf("%s: %v", token, err)
			}
			return msg
		}
		fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "qg_oauth", "database": "queryguard"}})
		if err := fe.Flush(); err != nil {
			t.Fatal(err)
		}
		if sasl, ok := receive().(*pgproto3.AuthenticationSASL); !ok || !slices.Contains(sasl.AuthMechanisms, "OAUTHBEARER") {
			t.Fatalf("%s: want AuthenticationSASL offering OAUTHBEARER, got %#v", token, sasl)
		}
		// RFC 7628's initial client response: a gs2 header without channel binding, then the bearer token.
		fe.Send(&pgproto3.SASLInitialResponse{AuthMechanism: "OAUTHBEARER", Data: []byte("n,,\x01auth=Bearer " + token + "\x01\x01")})
		if err := fe.Flush(); err != nil {
			t.Fatal(err)
		}

		if !wantOK {
			challenge, ok := receive().(*pgproto3.AuthenticationSASLContinue)
			if !ok || !strings.Contains(string(challenge.Data), "invalid_token") {
				t.Fatalf("stolen token: want a SASL challenge with invalid_token, got %#v", challenge)
			}
			fe.Send(&pgproto3.SASLResponse{Data: []byte{0x01}})
			if err := fe.Flush(); err != nil {
				t.Fatal(err)
			}
			if e, ok := receive().(*pgproto3.ErrorResponse); !ok || e.Code != "28000" {
				t.Fatalf("stolen token: want ErrorResponse 28000, got %#v", e)
			}
			continue
		}
		if _, ok := receive().(*pgproto3.AuthenticationOk); !ok {
			t.Fatalf("good token: want AuthenticationOk")
		}
		for {
			if _, ok := receive().(*pgproto3.ReadyForQuery); ok {
				break
			}
		}
		fe.Send(&pgproto3.Query{String: "select current_user"})
		if err := fe.Flush(); err != nil {
			t.Fatal(err)
		}
		var user string
		for msg := receive(); ; msg = receive() {
			if row, ok := msg.(*pgproto3.DataRow); ok {
				user = string(row.Values[0])
			}
			if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
				break
			}
		}
		if user != "qg_oauth" {
			t.Errorf("good token: current_user is %q, want qg_oauth", user)
		}
	}
}
