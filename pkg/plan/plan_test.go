package plan

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// update and count are trimmed from EXPLAIN (FORMAT JSON, VERBOSE) on Postgres 18 over the test schema.
const (
	update = `[{"Plan": {"Node Type": "ModifyTable", "Operation": "Update", "Relation Name": "orders", "Schema": "public", "Total Cost": 241255.31,
		"Plans": [{"Node Type": "Seq Scan", "Relation Name": "orders", "Schema": "public", "Total Cost": 241255.31}]}}]`
	count = `[{"Plan": {"Node Type": "Aggregate", "Total Cost": 169340.33, "Plans": [{"Node Type": "Gather", "Total Cost": 169340.31,
		"Plans": [{"Node Type": "Seq Scan", "Parallel Aware": true, "Relation Name": "orders", "Schema": "public", "Total Cost": 168340.21}]}]}}]`
	join = `[{"Plan": {"Node Type": "Nested Loop", "Total Cost": 153818.34, "Plans": [
		{"Node Type": "Result", "Parent Relationship": "InitPlan", "Total Cost": 0.25, "Plans": [
			{"Node Type": "Seq Scan", "Relation Name": "tenants", "Schema": "public", "Total Cost": 2}]},
		{"Node Type": "Index Scan", "Relation Name": "customers", "Schema": "public", "Total Cost": 8.44},
		{"Node Type": "Seq Scan", "Relation Name": "tenants", "Schema": "public", "Total Cost": 2}]},
		"Query Identifier": 860734387597997790, "JIT": {"Functions": 12}}]`
)

func TestParse(t *testing.T) {
	for name, tc := range map[string]struct {
		out  string
		want Plan
	}{
		"update":               {update, Plan{Cost: 241255.31, SeqScans: []Table{{"public", "orders"}}}},
		"parallel scan":        {count, Plan{Cost: 169340.33, SeqScans: []Table{{"public", "orders"}}}},
		"nested, listed once":  {join, Plan{Cost: 153818.34, SeqScans: []Table{{"public", "tenants"}}}},
		"no scan of any table": {`[{"Plan": {"Node Type": "Result", "Total Cost": 0.01}}]`, Plan{Cost: 0.01}},
		// A DO ALSO rule adds a second query, and so a second plan; DO INSTEAD NOTHING leaves none.
		"rewritten into two": {`[{"Plan": {"Node Type": "ModifyTable", "Total Cost": 0.01}}, {"Plan": {"Node Type": "Seq Scan", "Schema": "public", "Relation Name": "log", "Total Cost": 2.5}}]`,
			Plan{Cost: 2.51, SeqScans: []Table{{"public", "log"}}}},
		"rewritten into nothing": {`[]`, Plan{}},
	} {
		got, err := Parse(tc.out)
		if err != nil || got.Cost != tc.want.Cost || !slices.Equal(got.SeqScans, tc.want.SeqScans) {
			t.Errorf("%s: Parse = %+v, %v; want %+v", name, got, err, tc.want)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, out := range []string{"", `{"Plan": {}}`, `[{"Plan": {"Node Type": "Result", "Total Cost": "x"}}]`, `[{"Query Identifier": 1}]`} {
		if _, err := Parse(out); err == nil {
			t.Errorf("Parse(%q) succeeded; want an error", out)
		}
	}
}

func TestCacheExplainsOnceUntilTTL(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := &Cache{TTL: time.Minute, RefreshOneIn: -1}
		calls := 0
		explain := func() (Plan, error) {
			calls++
			time.Sleep(3 * time.Millisecond) // a round trip to Postgres
			return Plan{Cost: float64(calls)}, nil
		}

		first, _ := c.Get("a", explain)
		again, _ := c.Get("a", explain)
		other, _ := c.Get("b", explain)
		time.Sleep(time.Minute)
		expired, _ := c.Get("a", explain)

		if first.Cost != 1 || again.Cost != 1 || other.Cost != 2 || expired.Cost != 3 {
			t.Errorf("costs %v %v %v %v; want 1 1 2 3", first.Cost, again.Cost, other.Cost, expired.Cost)
		}
		want := Stats{Hits: 1, Misses: 3, Explaining: 9 * time.Millisecond, Slowest: 3 * time.Millisecond}
		if got := c.Stats(); got != want {
			t.Errorf("Stats = %+v; want %+v", got, want)
		}
	})
}

func TestCacheExplainsSomeHitsAgain(t *testing.T) {
	c := &Cache{RefreshOneIn: 1}
	calls := 0
	explain := func() (Plan, error) { calls++; return Plan{Cost: float64(calls)}, nil }

	got := []float64{}
	for range 4 {
		p, _ := c.Get("a", explain)
		got = append(got, p.Cost)
	}

	// One in one explains every hit again.
	if !slices.Equal(got, []float64{1, 2, 3, 4}) || c.Stats().Misses != 4 {
		t.Errorf("costs %v, stats %+v; want 1 2 3 4 from 4 explains", got, c.Stats())
	}
}

func TestCacheKeepsNoFailures(t *testing.T) {
	c := &Cache{}
	failed := errors.New("no plan")

	if _, err := c.Get("a", func() (Plan, error) { return Plan{}, failed }); !errors.Is(err, failed) {
		t.Fatalf("Get = %v; want the explain error", err)
	}
	if p, err := c.Get("a", func() (Plan, error) { return Plan{Cost: 5}, nil }); err != nil || p.Cost != 5 {
		t.Errorf("Get after a failure = %+v, %v; want a fresh explain", p, err)
	}
}

func TestCacheStaysWithinSize(t *testing.T) {
	c := &Cache{Size: 2}
	for _, key := range []string{"a", "b", "c", "d"} {
		c.Get(key, func() (Plan, error) { return Plan{}, nil })
	}
	if n := len(c.entries); n > 2 {
		t.Errorf("cache holds %d entries; want at most 2", n)
	}
}

func TestCatalogLoadsOnFirstUseAndRefreshesInBackground(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var loads atomic.Int32
		c := &Catalog{Interval: time.Minute, load: func(_ context.Context, database string) (map[Table]float64, error) {
			n := loads.Add(1)
			return map[Table]float64{{"public", database}: float64(n * 100)}, nil
		}}
		orders := Table{"public", "shop"}

		first, ok := c.Rows("shop", orders)
		if !ok || first != 100 {
			t.Fatalf("first Rows = %v, %v; want 100 loaded right away", first, ok)
		}
		if _, ok := c.Rows("shop", Table{"public", "missing"}); ok {
			t.Error("a table the catalog doesn't list has a size")
		}
		time.Sleep(time.Minute + time.Second)
		stale, _ := c.Rows("shop", orders)
		synctest.Wait()
		fresh, _ := c.Rows("shop", orders)

		// The stale read answers at once; the reload it starts serves the next one.
		if stale != 100 || fresh != 200 || loads.Load() != 2 {
			t.Errorf("stale %v, fresh %v after %d loads; want 100, 200 after 2", stale, fresh, loads.Load())
		}
	})
}

func TestCatalogKeepsDatabasesApart(t *testing.T) {
	c := &Catalog{load: func(_ context.Context, database string) (map[Table]float64, error) {
		return map[Table]float64{{"public", "t"}: float64(len(database))}, nil
	}}
	a, _ := c.Rows("ab", Table{"public", "t"})
	b, _ := c.Rows("abcd", Table{"public", "t"})
	if a != 2 || b != 4 {
		t.Errorf("sizes %v and %v; want 2 and 4", a, b)
	}
}

func TestCatalogWithoutSizesAfterFailedLoad(t *testing.T) {
	c := &Catalog{load: func(context.Context, string) (map[Table]float64, error) { return nil, errors.New("refused") }}
	if rows, ok := c.Rows("shop", Table{"public", "orders"}); ok {
		t.Errorf("Rows = %v after a failed load; want unknown", rows)
	}
}
