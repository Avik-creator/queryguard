package compat

import (
	"io"
	"os"
	"slices"
	"testing"
	"time"
)

// BenchmarkOverhead compares query latency straight to Postgres with latency through QueryGuard.
func BenchmarkOverhead(b *testing.B) {
	qg := startProxy(b)
	rules := startRulesProxy(b, io.Discard)
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
