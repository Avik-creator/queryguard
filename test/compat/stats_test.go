package compat

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Avik-creator/queryguard/pkg/plan"
	"github.com/Avik-creator/queryguard/pkg/proxy"
	"github.com/Avik-creator/queryguard/pkg/sqlparse"
	"github.com/Avik-creator/queryguard/pkg/stats"
	"github.com/jackc/pgx/v5"
)

func TestStatsCountEveryQueryModeByTenant(t *testing.T) {
	table := &stats.Table{}
	qg := startProxyWith(t, func(s *proxy.Server) {
		s.Policy = mustPolicy(t, `{"trusted_roles": ["postgres"]}`)
		s.Stats = table
	})
	conn := qg.connect(t, "")
	ctx := t.Context()

	const bound = "select $1::int + 1 as stats_probe"
	for i := range 3 {
		var n int
		if err := conn.QueryRow(ctx, bound, i).Scan(&n); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.Exec(ctx, "select 42 as stats_probe_simple", pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "select 1/0 as stats_probe"); sqlState(err) != "22012" {
		t.Fatalf("got %v; want division by zero", err)
	}
	if _, err := conn.Exec(ctx, "select 2 as stats_probe /*tenant='acme'*/"); err != nil {
		t.Fatal(err)
	}

	var rows []stats.Row
	byFingerprint := func(sql, tenant string) (stats.Row, bool) {
		for _, r := range rows {
			if r.Fingerprint == sqlparse.Fingerprint(sql) && r.Tenant == tenant {
				return r, true
			}
		}
		return stats.Row{}, false
	}
	waitFor(t, 5*time.Second, func() bool {
		rows = table.Rows()
		r, ok := byFingerprint("select 2 as stats_probe", "acme")
		return ok && r.Calls == 1
	})

	if r, _ := byFingerprint(bound, "postgres"); r.Calls != 3 || r.Timed != 3 || r.Rows != 3 || r.P99 <= 0 || r.Database != "queryguard" {
		t.Errorf("extended protocol row %+v; want 3 timed calls of one row each", r)
	}
	if r, _ := byFingerprint("select 1 as stats_probe_simple", "postgres"); r.Calls != 1 || r.Rows != 1 {
		t.Errorf("simple protocol row %+v; want one call", r)
	}
	if r, _ := byFingerprint("select 1/0 as stats_probe", "postgres"); r.Errors["22012"] != 1 {
		t.Errorf("error row %+v; want one division by zero", r)
	}
}

func TestStatsTakeBuffersAndTempSpillsFromPgStatStatements(t *testing.T) {
	table := &stats.Table{}
	qg := startProxyWith(t, func(s *proxy.Server) {
		s.Stats = table
		s.Monitor = &plan.Monitor{DSN: catalogDSN(t), StatementsEvery: 100 * time.Millisecond, Interval: 100 * time.Millisecond}
	})
	admin, err := pgx.Connect(t.Context(), catalogDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	mustExec(t, admin, "create extension if not exists pg_stat_statements")
	conn := qg.connect(t, "")

	// A sort bigger than work_mem spills to temporary files.
	mustExec(t, conn, "set work_mem = '64kB'")
	const spill = "select g from generate_series(1, 200000) g order by g desc limit 1"
	mustExec(t, conn, spill)

	waitFor(t, 10*time.Second, func() bool {
		for _, r := range table.Rows() {
			if r.Fingerprint == sqlparse.Fingerprint(spill) && r.Buffers.Calls > 0 && r.Buffers.TempWritten > 0 {
				return true
			}
		}
		return false
	})
}

func TestStatsCallsMatchPgStatStatementsUnderLoad(t *testing.T) {
	table := &stats.Table{}
	qg := startProxyWith(t, func(s *proxy.Server) { s.Stats = table })
	admin := connectTo(t, os.Getenv("QG_TEST_UPSTREAM"), "sslmode=disable")
	mustExec(t, admin, "create extension if not exists pg_stat_statements")

	// pg_stat_statements' query ID ignores aliases and comments but not tables, so a table of its own keeps this run apart.
	marker := fmt.Sprintf("qg_calls_%d", time.Now().UnixNano())
	mustExec(t, admin, "create table "+marker+" as select 0 as id")
	t.Cleanup(func() { admin.Exec(context.Background(), "drop table "+marker) })
	statements := []struct {
		sql  string
		mode pgx.QueryExecMode
		args []any
	}{
		{"select count(*) from " + marker + " where id = $1", pgx.QueryExecModeCacheStatement, []any{7}},
		{"select id from " + marker + " where id > $1", pgx.QueryExecModeExec, []any{-1}},
		{"select id from " + marker, pgx.QueryExecModeSimpleProtocol, nil},
		{"select 1/id from " + marker, pgx.QueryExecModeCacheStatement, nil},
	}
	const workers, rounds = 8, 48
	var wg sync.WaitGroup
	for range workers {
		conn := qg.connect(t, "sslmode=disable")
		wg.Go(func() {
			for i := range rounds {
				st := statements[i%len(statements)]
				conn.Exec(t.Context(), st.sql, append([]any{st.mode}, st.args...)...)
			}
		})
	}
	wg.Wait()

	// pg_stat_statements counts only statements that finished without an error.
	var want int64
	if err := admin.QueryRow(t.Context(), "select coalesce(sum(calls), 0)::int8 from pg_stat_statements where query like 'select %' || $1 || '%'",
		marker).Scan(&want); err != nil {
		t.Fatal(err)
	}
	if want != workers*rounds*3/4 {
		t.Fatalf("pg_stat_statements counted %d calls; want %d", want, workers*rounds*3/4)
	}
	var calls, errs int64
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		calls, errs = 0, 0
		for _, r := range table.Rows() {
			if strings.Contains(r.Query, marker) {
				calls += r.Calls
				errs += r.Errors["22012"]
			}
		}
		if calls == workers*rounds {
			break
		}
	}
	if calls-errs != want || errs != workers*rounds/4 || table.Dropped() != 0 {
		t.Errorf("QueryGuard counted %d calls with %d errors (%d dropped); want %d calls, %d without an error as pg_stat_statements has",
			calls, errs, table.Dropped(), workers*rounds, want)
	}
}
