package compat

import (
	"context"
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
