package compat

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/Avik-creator/queryguard/pkg/plan"
	"github.com/Avik-creator/queryguard/pkg/policy"
	"github.com/Avik-creator/queryguard/pkg/proxy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// rulesConfig blocks UPDATE and DELETE without WHERE and only logs DDL, so tests can still make temp tables.
const rulesConfig = `{"rules": [{"check": "require_where"}, {"check": "deny_ddl", "mode": "warn"}]}`

// blockedDelete makes a statement fail in Postgres with 42P01 if the proxy ever lets it through.
const blockedDelete = "delete from qg_no_such_table"

func TestPgxRejectedStatementLeavesConnectionUsable(t *testing.T) {
	conn := startRulesProxy(t, io.Discard).connect(t, "sslmode=disable")
	for _, mode := range []pgx.QueryExecMode{pgx.QueryExecModeCacheStatement, pgx.QueryExecModeExec, pgx.QueryExecModeSimpleProtocol} {
		_, err := conn.Exec(t.Context(), blockedDelete, mode)

		expectRejected(t, mode.String(), err)
		expectSelectOne(t, conn)
	}
}

func TestPgxRejectionInTransactionFailsIt(t *testing.T) {
	conn := startRulesProxy(t, io.Discard).connect(t, "sslmode=disable")
	ctx := t.Context()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}

	_, err = tx.Exec(ctx, blockedDelete)

	expectRejected(t, "in transaction", err)
	if _, err := tx.Exec(ctx, "select 1"); sqlState(err) != "25P02" {
		t.Errorf("next statement got %v; want 25P02 in_failed_sql_transaction", err)
	}
	if err := tx.Commit(ctx); !errors.Is(err, pgx.ErrTxCommitRollback) {
		t.Errorf("COMMIT got %v; want it to roll back", err)
	}
	expectSelectOne(t, conn)
}

func TestPgxRejectionInPipelineRollsBackEarlierStatements(t *testing.T) {
	conn := startRulesProxy(t, io.Discard).connect(t, "sslmode=disable")
	ctx := t.Context()
	if _, err := conn.Exec(ctx, "create temp table qg_pipeline (id int)"); err != nil {
		t.Fatal(err)
	}

	// One Sync covers both statements, so Postgres runs them in one implicit transaction.
	p := conn.PgConn().StartPipeline(ctx)
	p.SendQueryParams("insert into qg_pipeline values (1)", nil, nil, nil, nil)
	p.SendQueryParams("delete from qg_pipeline", nil, nil, nil, nil)
	p.SendPipelineSync()
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	err := p.Close()

	expectRejected(t, "pipeline", err)
	var rows int
	if err := conn.QueryRow(ctx, "select count(*) from qg_pipeline").Scan(&rows); err != nil || rows != 0 {
		t.Errorf("table has %d rows, %v; want the insert rolled back with the rejected delete", rows, err)
	}
}

func TestWarnModeLogsWouldBeRejection(t *testing.T) {
	var logs lockedBuffer
	conn := startRulesProxy(t, &logs).connect(t, "sslmode=disable")

	if _, err := conn.Exec(t.Context(), "create temp table qg_warned (id int)"); err != nil {
		t.Fatalf("warn mode blocked DDL: %v", err)
	}

	if got := logs.String(); !strings.Contains(got, `msg="would reject statement"`) || !strings.Contains(got, "rule=deny_ddl") {
		t.Errorf("log %q; want the would-be rejection", got)
	}
}

func TestConnectionCap(t *testing.T) {
	qg := startProxyWith(t, func(s *proxy.Server) { s.Policy = mustPolicy(t, `{"max_connections": 1}`) })
	qg.connect(t, "sslmode=disable")

	_, err := pgx.Connect(t.Context(), "host=127.0.0.1 port="+port(qg)+" user=postgres dbname=queryguard sslmode=disable password="+password())

	if sqlState(err) != "53300" {
		t.Errorf("second connection got %v; want 53300 too_many_connections", err)
	}
}

// costConfig sets both cost rules at half of what a full read of orders takes, whatever the size of the test data, so
// such a read is blocked while index lookups and full reads of the 100-row tenants stay well under both limits.
func costConfig(t testing.TB) string {
	t.Helper()
	conn := connectTo(t, os.Getenv("QG_TEST_UPSTREAM"), "sslmode=disable")
	var out string
	var rows float64
	if err := conn.QueryRow(t.Context(), "explain (format json) select count(*) from orders where note = 'x'").Scan(&out); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(t.Context(), "select reltuples from pg_class where oid = 'orders'::regclass").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	p, err := plan.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if p.Cost/2 < 20 || rows/2 < 200 {
		t.Fatalf("orders is too small for the cost tests: a full read costs %.0f and it has %.0f rows", p.Cost, rows)
	}
	return fmt.Sprintf(`{"rules": [{"check": "max_cost", "cost": %.0f}, {"check": "max_scan_rows", "rows": %.0f}]}`, p.Cost/2, rows/2)
}

func TestPgxCostRules(t *testing.T) {
	conn := startCostProxy(t, nil).connect(t, "sslmode=disable")
	for _, mode := range []pgx.QueryExecMode{pgx.QueryExecModeCacheStatement, pgx.QueryExecModeExec, pgx.QueryExecModeSimpleProtocol} {
		for _, tc := range []struct {
			sql  string
			arg  any
			want string // the rule that blocks it
		}{
			{"select id from orders where id = $1", 7, ""},
			{"select count(*) from orders where note = $1", "x", "max_cost"},
			// Cheap, but it starts a full read of orders that a WHERE clause would turn into a slow one.
			{"select * from orders where total_cents > $1 limit 1", 0, "max_scan_rows"},
			{"select * from tenants where name <> $1", "x", ""},
		} {
			_, err := conn.Exec(t.Context(), tc.sql, mode, tc.arg)
			if tc.want == "" {
				if err != nil {
					t.Errorf("%s: %s failed: %v", mode, tc.sql, err)
				}
				continue
			}
			if pgErr, ok := errors.AsType[*pgconn.PgError](err); !ok || pgErr.Code != "54000" || !strings.Contains(pgErr.Message, tc.want) {
				t.Errorf("%s: %s got %v; want 54000 from %s", mode, tc.sql, err, tc.want)
			}
			expectSelectOne(t, conn)
		}
	}
}

func TestCostCheckPassesOnPostgresErrors(t *testing.T) {
	conn := startCostProxy(t, nil).connect(t, "sslmode=disable")
	direct := connectTo(t, os.Getenv("QG_TEST_UPSTREAM"), "sslmode=disable")
	const sql = "select id, nosuchcolumn from orders"

	_, want := direct.Exec(t.Context(), sql, pgx.QueryExecModeSimpleProtocol)
	_, got := conn.Exec(t.Context(), sql, pgx.QueryExecModeSimpleProtocol)

	// The client sees the error its own statement would get, pointing into its own text.
	wantErr, _ := errors.AsType[*pgconn.PgError](want)
	gotErr, ok := errors.AsType[*pgconn.PgError](got)
	if !ok || wantErr == nil || gotErr.Code != wantErr.Code || gotErr.Position != wantErr.Position {
		t.Errorf("through the proxy: %v at %d; straight to Postgres: %v at %d", got, gotErr.Position, want, wantErr.Position)
	}
	expectSelectOne(t, conn)
}

func TestPgxCostRejectionInTransactionFailsIt(t *testing.T) {
	conn := startCostProxy(t, nil).connect(t, "sslmode=disable")
	ctx := t.Context()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}

	_, err = tx.Exec(ctx, "select count(*) from orders where note = $1", "x")

	if sqlState(err) != "54000" {
		t.Errorf("costly statement got %v; want 54000", err)
	}
	if _, err := tx.Exec(ctx, "select 1"); sqlState(err) != "25P02" {
		t.Errorf("next statement got %v; want 25P02 in_failed_sql_transaction", err)
	}
	tx.Rollback(ctx)
	expectSelectOne(t, conn)
}

func TestPlanCacheServesRepeatedStatements(t *testing.T) {
	var s *proxy.Server
	conn := startCostProxy(t, func(srv *proxy.Server) { s = srv }).connect(t, "sslmode=disable")

	for id := range 5 {
		var got int64
		if err := conn.QueryRow(t.Context(), "select id from orders where id = $1", id+1).Scan(&got); err != nil {
			t.Fatal(err)
		}
	}

	if st := s.PlanStats(); st.Misses != 1 || st.Hits != 4 {
		t.Errorf("plan cache %+v; want 1 miss and 4 hits", st)
	}
}

func TestCatalogReadsTableSizes(t *testing.T) {
	c := &plan.Catalog{DSN: catalogDSN(t)}
	var want float64
	direct := connectTo(t, os.Getenv("QG_TEST_UPSTREAM"), "sslmode=disable")
	if err := direct.QueryRow(t.Context(), "select reltuples from pg_class where oid = 'orders'::regclass").Scan(&want); err != nil {
		t.Fatal(err)
	}

	rows, ok := c.Rows("queryguard", plan.Table{Schema: "public", Name: "orders"})

	if !ok || rows != want || rows <= 0 {
		t.Errorf("orders has %v rows (%v); want pg_class's %v", rows, ok, want)
	}
}

// startCostProxy starts a proxy with costConfig and a catalog, letting configure see the server too.
func startCostProxy(t testing.TB, configure func(*proxy.Server)) *queryGuard {
	t.Helper()
	return startProxyWith(t, func(s *proxy.Server) {
		s.Policy = mustPolicy(t, costConfig(t))
		s.Catalog = &plan.Catalog{DSN: catalogDSN(t)}
		if configure != nil {
			configure(s)
		}
	})
}

// catalogDSN connects straight to QG_TEST_UPSTREAM as the docker compose superuser.
func catalogDSN(t testing.TB) string {
	t.Helper()
	host, port, err := net.SplitHostPort(os.Getenv("QG_TEST_UPSTREAM"))
	if err != nil {
		t.Skip("set QG_TEST_UPSTREAM to a Postgres host:port")
	}
	return fmt.Sprintf("host=%s port=%s user=postgres password=%s sslmode=disable", host, port, password())
}

// startRulesProxy starts a proxy with rulesConfig that logs to logs.
func startRulesProxy(t testing.TB, logs io.Writer) *queryGuard {
	t.Helper()
	return startProxyWith(t, func(s *proxy.Server) {
		s.Policy = mustPolicy(t, rulesConfig)
		s.Logger = slog.New(slog.NewTextHandler(io.MultiWriter(logs, t.Output()), nil))
	})
}

func mustPolicy(t testing.TB, config string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(config))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func expectRejected(t *testing.T, what string, err error) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" || !strings.Contains(pgErr.Message, "require_where") {
		t.Errorf("%s: got %v; want 42501 from rule require_where", what, err)
	}
}

func expectSelectOne(t *testing.T, conn *pgx.Conn) {
	t.Helper()
	var one int
	if err := conn.QueryRow(t.Context(), "select 1").Scan(&one); err != nil || one != 1 {
		t.Errorf("select 1 after the rejection = %d, %v", one, err)
	}
}

func sqlState(err error) string {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		return pgErr.Code
	}
	return ""
}

func port(qg *queryGuard) string {
	_, p, _ := strings.Cut(qg.addr, ":")
	return p
}

// lockedBuffer is a bytes.Buffer that session goroutines can log to while the test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
