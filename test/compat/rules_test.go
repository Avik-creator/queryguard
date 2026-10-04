package compat

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

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
