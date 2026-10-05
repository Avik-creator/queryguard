package compat

import (
	"testing"
	"time"

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
