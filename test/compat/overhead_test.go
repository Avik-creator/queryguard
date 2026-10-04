package compat

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Avik-creator/queryguard/pkg/proxy"
	"github.com/jackc/pgx/v5"
)

// BenchmarkOverhead compares query latency straight to Postgres with latency through QueryGuard.
func BenchmarkOverhead(b *testing.B) {
	qg := startProxy(b)
	rules := startRulesProxy(b, io.Discard)
	cost := startCostProxy(b, nil)
	upstream := os.Getenv("QG_TEST_UPSTREAM")

	for _, q := range []struct{ name, sql string }{
		{"select_1", "select 1"},
		{"1000_rows", "select g, md5(g::text) from generate_series(1, 1000) g"},
	} {
		for _, path := range []struct{ name, addr, opts string }{
			{"direct", upstream, "sslmode=disable"},
			{"proxy", qg.addr, "sslmode=disable"},
			{"proxy_TLS", qg.addr, "sslmode=verify-full sslrootcert=" + qg.caFile},
			{"proxy_rules", rules.addr, "sslmode=disable"},
			// The simple protocol sends the SQL every time, so every run is parsed and checked.
			{"proxy_rules_simple", rules.addr, "sslmode=disable default_query_exec_mode=simple_protocol"},
			// Every run is costed, nearly always from the plan cache.
			{"proxy_cost", cost.addr, "sslmode=disable"},
			{"proxy_cost_simple", cost.addr, "sslmode=disable default_query_exec_mode=simple_protocol"},
		} {
			b.Run(q.name+"/"+path.name, func(b *testing.B) {
				conn := connectTo(b, path.addr, path.opts)
				ctx := b.Context()
				var took []time.Duration
				for b.Loop() {
					start := time.Now()
					rows, err := conn.Query(ctx, q.sql)
					if err != nil {
						b.Fatal(err)
					}
					for rows.Next() {
					}
					if err := rows.Err(); err != nil {
						b.Fatal(err)
					}
					took = append(took, time.Since(start))
				}
				slices.Sort(took)
				b.ReportMetric(micros(took[len(took)*50/100]), "p50-µs")
				b.ReportMetric(micros(took[len(took)*99/100]), "p99-µs")
			})
		}
	}
}

func micros(d time.Duration) float64 { return float64(d) / float64(time.Microsecond) }

// Tenants for TestRogueTenant; the shared-role scenario tells them apart by tag instead.
var (
	innocents = []string{"qg_innocent_1", "qg_innocent_2", "qg_innocent_3"}
	rogue     = "qg_rogue"
)

// rogueBudget lets the rogue tenant spend about a third of one full read of the 10M-row orders table a second.
const rogueBudget = `{"rate": 50000, "burst": 200000, "min_charge": 100, "when_over": "reject"}`

// TestRogueTenant is M4's acceptance test: innocent tenants' latency next to a rogue one, with and without QueryGuard (QG_ROGUE=1).
func TestRogueTenant(t *testing.T) {
	if os.Getenv("QG_ROGUE") == "" {
		t.Skip("set QG_ROGUE=1 to run the rogue-tenant benchmark")
	}
	upstream := os.Getenv("QG_TEST_UPSTREAM")
	createTenantRoles(t, connectTo(t, upstream, "sslmode=disable"))
	perRole := startProxyWith(t, func(s *proxy.Server) {
		s.Policy = mustPolicy(t, `{"scheduler": {"max_active": 8}, "tenants": {"`+rogue+`": {"budget": `+rogueBudget+`}}}`)
	})
	shared := startProxyWith(t, func(s *proxy.Server) {
		s.Policy = mustPolicy(t, `{"scheduler": {"max_active": 8}, "trusted_roles": ["qg_app"], "tenants": {"`+rogue+`": {"budget": `+rogueBudget+`}}}`)
	})

	// QueryGuard's scenarios are held against a baseline through it, so they measure the rogue, not the proxy's overhead.
	direct := runTenants(t, upstream, false, false)
	proxied := runTenants(t, perRole.addr, false, false)
	report := func(name string, r tenantRun) {
		t.Logf("%-42s innocent p50 %6.2f ms  p99 %7.2f ms  rogue ran %d, refused %d", name, ms(r.p50), ms(r.p99), r.rogueRan, r.rogueRefused)
	}
	report("baseline, straight to Postgres", direct)
	report("baseline, QueryGuard", proxied)
	for _, sc := range []struct {
		name       string
		addr       string
		sharedRole bool
		baseline   tenantRun
		inTarget   bool
	}{
		{"rogue, straight to Postgres", upstream, false, direct, false},
		{"rogue, QueryGuard, a role per tenant", perRole.addr, false, proxied, true},
		{"rogue, QueryGuard, shared role and tags", shared.addr, true, proxied, true},
	} {
		got := runTenants(t, sc.addr, true, sc.sharedRole)
		report(sc.name, got)
		// The target is 1.5 times the baseline p99; a millisecond of slack keeps a sub-millisecond baseline from being too strict.
		if limit := sc.baseline.p99*3/2 + time.Millisecond; sc.inTarget && got.p99 > limit {
			t.Errorf("%s: innocent p99 %v; want within %v", sc.name, got.p99, limit)
		}
	}
}

// tenantRun is what one scenario measured.
type tenantRun struct {
	p50, p99               time.Duration // innocent statements' latency
	rogueRan, rogueRefused int
}

// runTenants runs the innocent tenants for a few seconds, with the rogue tenant alongside when withRogue is set.
func runTenants(t *testing.T, addr string, withRogue, sharedRole bool) tenantRun {
	t.Helper()
	const duration = 15 * time.Second
	ctx, stop := context.WithTimeout(t.Context(), duration)
	defer stop()
	var (
		mu    sync.Mutex
		took  []time.Duration
		run   tenantRun
		group sync.WaitGroup
	)
	user := func(tenant string) (role, tag string) {
		if sharedRole {
			return "qg_app", fmt.Sprintf(" /*tenant='%s'*/", tenant)
		}
		return tenant, ""
	}
	if withRogue {
		for range 6 {
			role, tag := user(rogue)
			conn := connectTo(t, addr, "sslmode=disable user="+role+" password="+password())
			group.Go(func() {
				for ctx.Err() == nil {
					_, err := conn.Exec(ctx, "select count(*) from orders where note = $1"+tag, "x")
					mu.Lock()
					if err != nil {
						run.rogueRefused++
					} else {
						run.rogueRan++
					}
					mu.Unlock()
					if err != nil {
						// A rogue client retries at once; the pause only keeps the test's own CPU use down.
						time.Sleep(5 * time.Millisecond)
					}
				}
			})
		}
	}
	for _, tenant := range innocents {
		for range 2 {
			role, tag := user(tenant)
			conn := connectTo(t, addr, "sslmode=disable user="+role+" password="+password())
			group.Go(func() {
				for ctx.Err() == nil {
					start := time.Now()
					var id int64
					err := conn.QueryRow(ctx, "select id from orders where id = $1"+tag, rand.Int64N(1_000_000)+1).Scan(&id)
					if err != nil {
						continue
					}
					mu.Lock()
					took = append(took, time.Since(start))
					mu.Unlock()
				}
			})
		}
	}
	group.Wait()
	if len(took) == 0 {
		t.Fatal("no innocent statement finished")
	}
	slices.Sort(took)
	run.p50, run.p99 = took[len(took)*50/100], took[len(took)*99/100]
	return run
}

// createTenantRoles makes the roles the benchmark logs in as, if they don't exist, with read access to orders.
func createTenantRoles(t *testing.T, conn *pgx.Conn) {
	t.Helper()
	for _, role := range append(slices.Clone(innocents), rogue, "qg_app") {
		create := fmt.Sprintf(`do $$ begin
			if not exists (select from pg_roles where rolname = '%[1]s') then create role %[1]s login password '%[2]s'; end if;
		end $$`, role, password())
		if _, err := conn.Exec(t.Context(), create); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(t.Context(), "grant select on orders to "+role); err != nil {
			t.Fatal(err)
		}
	}
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
