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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Avik-creator/queryguard/internal/testcert"
	"github.com/Avik-creator/queryguard/pkg/proxy"
	"github.com/Avik-creator/queryguard/pkg/wire"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
		"tcp_user_timeout":        "30000",
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
	upstream := os.Getenv("QG_TEST_UPSTREAM")
	if upstream == "" {
		t.Skip("set QG_TEST_UPSTREAM to a Postgres host:port, for example 127.0.0.1:5418 after make up")
	}

	cert, _ := testcert.Pair(t)
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
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
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return &queryGuard{addr: ln.Addr().String(), caFile: caFile}
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
