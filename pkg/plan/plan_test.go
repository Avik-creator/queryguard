package plan

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
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
		c := &Catalog{Interval: time.Minute, load: func(_ context.Context, database string) (map[Table]stats, error) {
			n := loads.Add(1)
			return map[Table]stats{{"public", database}: {rows: float64(n * 100)}}, nil
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
	c := &Catalog{load: func(_ context.Context, database string) (map[Table]stats, error) {
		return map[Table]stats{{"public", "t"}: {rows: float64(len(database))}}, nil
	}}
	a, _ := c.Rows("ab", Table{"public", "t"})
	b, _ := c.Rows("abcd", Table{"public", "t"})
	if a != 2 || b != 4 {
		t.Errorf("sizes %v and %v; want 2 and 4", a, b)
	}
}

func TestCatalogWithoutSizesAfterFailedLoad(t *testing.T) {
	c := &Catalog{load: func(context.Context, string) (map[Table]stats, error) { return nil, errors.New("refused") }}
	if rows, ok := c.Rows("shop", Table{"public", "orders"}); ok {
		t.Errorf("Rows = %v after a failed load; want unknown", rows)
	}
}

func TestCatalogWithoutSizesAfterALoadPanics(t *testing.T) {
	var logs bytes.Buffer
	c := &Catalog{Log: slog.New(slog.NewTextHandler(&logs, nil)),
		load: func(context.Context, string) (map[Table]stats, error) { panic("bug") }}

	if rows, ok := c.Rows("shop", Table{"public", "orders"}); ok {
		t.Errorf("Rows = %v after a load panicked; want unknown", rows)
	}
	if !strings.Contains(logs.String(), "bug") {
		t.Errorf("log %q; want the panic", logs.String())
	}
}

// lookup reads one order through its primary key; fullRead is the same statement once the index is gone.
const (
	lookup   = `[{"Plan": {"Node Type": "Index Scan", "Relation Name": "orders", "Schema": "public", "Index Name": "orders_pkey", "Total Cost": 8.44}}]`
	fullRead = `[{"Plan": {"Node Type": "Seq Scan", "Relation Name": "orders", "Schema": "public", "Total Cost": 241255.31}}]`
	bitmap   = `[{"Plan": {"Node Type": "Bitmap Heap Scan", "Relation Name": "orders", "Schema": "public", "Total Cost": 912.5,
		"Plans": [{"Node Type": "Bitmap Index Scan", "Index Name": "orders_customer_idx", "Total Cost": 12.1}]}}]`
)

func mustParse(t *testing.T, out string) Plan {
	t.Helper()
	p, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseShape(t *testing.T) {
	a, cheaper, full := mustParse(t, lookup), mustParse(t, strings.Replace(lookup, "8.44", "4.45", 1)), mustParse(t, fullRead)

	if a.Shape == 0 || a.Shape != cheaper.Shape || a.Shape == full.Shape {
		t.Errorf("shapes %x, %x, %x; want the first two equal, since only the estimate differs, and the third apart", a.Shape, cheaper.Shape, full.Shape)
	}
}

func TestParseTablesReadThroughAnIndex(t *testing.T) {
	for out, want := range map[string][]Table{
		lookup:   {{"public", "orders"}},
		bitmap:   {{"public", "orders"}},
		join:     {{"public", "customers"}},
		fullRead: nil,
	} {
		if got := mustParse(t, out).Indexed; !slices.Equal(got, want) {
			t.Errorf("Indexed = %v; want %v in %s", got, want, out)
		}
	}
}

func TestHistoryFactorStartsAtOne(t *testing.T) {
	var h History
	if f := h.Judge("a", mustParse(t, lookup), Tuning{}).Factor; f != 1 {
		t.Errorf("Factor = %v with no runs; want 1", f)
	}
}

func TestHistoryCalibratesByMeasuredTime(t *testing.T) {
	for _, tc := range []struct {
		credibility float64
		weight      float64 // the share of a statement's own timing in its factor after 10 runs
	}{{0, 10.0 / 20}, {30, 10.0 / 40}} {
		var h History
		tune := Tuning{Credibility: tc.credibility}
		fast, slow := Plan{Cost: 100, Shape: 1}, Plan{Cost: 100, Shape: 2}
		for range 10 {
			h.Ran("", "fast", fast, 10*time.Millisecond, true, tune)
			h.Ran("", "slow", slow, 100*time.Millisecond, true, tune)
		}

		// Averaged in log terms, a cost unit takes 316µs; fast takes about 3.16 times less, slow 3.16 times more.
		got := []float64{h.Judge("fast", fast, tune).Factor, h.Judge("slow", slow, tune).Factor}
		want := []float64{math.Pow(10, -tc.weight/2), math.Pow(10, tc.weight/2)}
		for i := range got {
			if math.Abs(got[i]-want[i]) > 1e-9 {
				t.Errorf("credibility %v: factors %v; want %v", tc.credibility, got, want)
				break
			}
		}
	}
}

func TestHistoryLearnsCostOnlyFromLongRuns(t *testing.T) {
	var h History
	quick, long := Plan{Cost: 100, Shape: 1}, Plan{Cost: 100, Shape: 2}
	for range 10 {
		h.Ran("", "quick", quick, time.Millisecond, true, Tuning{})
		h.Ran("", "long", long, 100*time.Millisecond, true, Tuning{})
	}

	// A run of a millisecond is mostly the round trip and the work every statement does, so it says little about its plan.
	if q, l := h.Judge("quick", quick, Tuning{}).Factor, h.Judge("long", long, Tuning{}).Factor; q != 1 || math.Abs(l-1) > 1e-9 {
		t.Errorf("factors %v and %v; want 1 for both, the quick plan unlearned and the long one the server's only timing", q, l)
	}
}

func TestHistoryServerTimingWeighsRunsByCost(t *testing.T) {
	var h History
	big := Plan{Cost: 100_000, Shape: 1}
	for range 10 {
		h.Ran("", "big", big, time.Second, true, Tuning{})
	}
	before := h.Judge("big", big, Tuning{}).Factor

	// A cheap statement that waited ten seconds on a lock says little about how fast the server works through cost units.
	h.Ran("", "cheap", Plan{Cost: 1, Shape: 2}, 10*time.Second, true, Tuning{})

	if after := h.Judge("big", big, Tuning{}).Factor; math.Abs(after-before) > 0.01 {
		t.Errorf("factor %v, then %v after one cheap statement's long wait; want it about the same", before, after)
	}
}

func TestHistoryCostOfTime(t *testing.T) {
	var h History
	if c, ok := h.CostOf(time.Second); ok {
		t.Errorf("CostOf with nothing learned = %v; want unknown", c)
	}
	for range 10 {
		h.Ran("", "s", Plan{Cost: 1000, Shape: 1}, 100*time.Millisecond, true, Tuning{})
	}

	// 1000 cost units take 0.1s on this server, so a second is worth 10000 of them.
	if c, ok := h.CostOf(time.Second); !ok || math.Abs(c-10_000) > 1 {
		t.Errorf("CostOf(1s) = %v, %v; want 10000", c, ok)
	}
}

func TestOneTenantsRunsCountNoMoreThanAnothersInTheServerTiming(t *testing.T) {
	var h History
	for range 200 {
		h.Ran("shop", "s", Plan{Cost: 1000, Shape: 1}, 100*time.Millisecond, true, Tuning{})
	}
	// Ten times the runs, each a hundred times slower per cost unit, as a tenant stuck on its own locks would be.
	for range 2000 {
		h.Ran("rogue", "r", Plan{Cost: 1000, Shape: 1}, 10*time.Second, true, Tuning{})
	}

	// Counted alike, 0.1s and 10s per 1000 units meet at 1s, so a second is worth 1000 units.
	if c, ok := h.CostOf(time.Second); !ok || math.Abs(c-1000) > 10 {
		t.Errorf("CostOf(1s) = %v, %v; want 1000, each tenant's timing counting the same", c, ok)
	}
}

func TestATenantWithFewRunsCountsForLess(t *testing.T) {
	var h History
	for range 200 {
		h.Ran("shop", "s", Plan{Cost: 1000, Shape: 1}, 100*time.Millisecond, true, Tuning{})
	}
	h.Ran("new", "n", Plan{Cost: 1000, Shape: 1}, 10*time.Second, true, Tuning{})

	if c, ok := h.CostOf(time.Second); !ok || c < 9000 {
		t.Errorf("CostOf(1s) = %v, %v; want near 10000, one run of a new tenant moving it little", c, ok)
	}
}

func TestHistoryNewPlanLearnsItsOwnFactor(t *testing.T) {
	var h History
	p := mustParse(t, lookup)
	for range 10 {
		h.Ran("", "a", p, time.Millisecond, true, Tuning{})
		h.Ran("", "b", Plan{Cost: 100, Shape: 7}, 100*time.Millisecond, true, Tuning{})
	}

	if f := h.Judge("a", mustParse(t, fullRead), Tuning{}).Factor; f != 1 {
		t.Errorf("Factor = %v for a plan never run; want 1", f)
	}
}

func TestHistoryFlagsIndexScanTurningIntoFullRead(t *testing.T) {
	var h History
	usual, full := mustParse(t, lookup), mustParse(t, fullRead)
	for range minRuns - 1 {
		h.Ran("", "a", usual, time.Millisecond, true, Tuning{})
	}
	if v := h.Judge("a", full, Tuning{}); v.Flip != "" {
		t.Errorf("flagged %q after %d runs; want a flip only after %d", v.Flip, minRuns-1, minRuns)
	}
	h.Ran("", "a", usual, time.Millisecond, true, Tuning{})

	first, again, back := h.Judge("a", full, Tuning{}), h.Judge("a", full, Tuning{}), h.Judge("a", usual, Tuning{})

	if !strings.Contains(first.Flip, "public.orders") || !first.First || again.First || again.Flip != first.Flip {
		t.Errorf("full read judged %+v, then %+v; want a flip naming public.orders, first only once", first, again)
	}
	if back.Flip != "" {
		t.Errorf("the usual plan was flagged: %q", back.Flip)
	}
}

func TestHistoryTakesPlanForOtherValuesAsAnAlternative(t *testing.T) {
	var h History
	usual, full := mustParse(t, lookup), mustParse(t, fullRead)
	for range minRuns {
		h.Ran("", "a", usual, time.Millisecond, true, Tuning{})
	}

	// A common value reads the table in full while rare ones keep using the index: that is data, not a regression.
	var flagged []bool
	for range minRuns + 1 {
		flagged = append(flagged, h.Judge("a", full, Tuning{}).Flip != "")
		h.Ran("", "a", full, time.Second, true, Tuning{})
		h.Judge("a", usual, Tuning{})
		h.Ran("", "a", usual, time.Millisecond, true, Tuning{})
	}

	if !flagged[0] || flagged[minRuns] {
		t.Errorf("full read flagged %v run by run; want it flagged at first and taken as an alternative once it ran %d times beside the usual plan",
			flagged, minRuns)
	}
}

func TestHistoryDoesNotFlagABetterPlan(t *testing.T) {
	var h History
	for range minRuns {
		h.Ran("", "a", mustParse(t, fullRead), time.Second, true, Tuning{})
	}
	if v := h.Judge("a", mustParse(t, lookup), Tuning{}); v.Flip != "" {
		t.Errorf("an index scan replacing a full read was flagged: %q", v.Flip)
	}
}

func TestHistoryTakesANewPlanAsUsualAfterQuarantine(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var h History
		tune := Tuning{Quarantine: 10 * time.Minute}
		usual, full := mustParse(t, lookup), mustParse(t, fullRead)
		for range 10 {
			h.Ran("", "a", usual, time.Millisecond, true, tune)
		}

		var flagged []bool
		for range 30 {
			time.Sleep(time.Minute)
			flagged = append(flagged, h.Judge("a", full, tune).Flip != "")
			h.Ran("", "a", full, time.Second, true, tune)
		}

		// The old plan's runs fade with the quarantine as half-life, so the new one outweighs them in about that time.
		if !flagged[0] || !flagged[5] || flagged[29] {
			t.Errorf("full read flagged %v minute by minute; want it flagged at first and taken as usual by the end", flagged)
		}
	})
}

func TestHistoryFlagsRunFarSlowerThanPlanned(t *testing.T) {
	var h History
	p := mustParse(t, lookup)
	if h.Ran("", "a", p, time.Millisecond, true, Tuning{}) || h.Ran("", "a", p, 5*time.Second, true, Tuning{}) {
		t.Fatal("a slow run was flagged before the plan had a timing to compare with")
	}
	h = History{}
	for range minRuns {
		h.Ran("", "a", p, time.Millisecond, true, Tuning{})
	}

	slow := h.Ran("", "a", p, 2*time.Second, true, Tuning{})
	flagged := h.Judge("a", p, Tuning{})
	again := h.Ran("", "a", p, 2*time.Second, true, Tuning{})
	h.Ran("", "a", p, time.Millisecond, true, Tuning{})
	cleared := h.Judge("a", p, Tuning{})

	// Only the run that turns the plan slow is reported, so a plan that stays slow isn't reported on every run.
	if !slow || again || !strings.Contains(flagged.Flip, "slower") || !flagged.First || cleared.Flip != "" {
		t.Errorf("slow runs %v and %v, judged %+v, then %+v after a normal run; want the first reported and flagged, then cleared",
			slow, again, flagged, cleared)
	}
}

func TestHistoryDoesNotFlagShortSlowRun(t *testing.T) {
	var h History
	p := mustParse(t, lookup)
	for range minRuns {
		h.Ran("", "a", p, time.Millisecond, true, Tuning{})
	}

	// Under load a lookup now and then takes tens of milliseconds, which is no reason to move it to the slow lane.
	if h.Ran("", "a", p, 50*time.Millisecond, true, Tuning{}) || h.Judge("a", p, Tuning{}).Flip != "" {
		t.Error("a run 50 times slower than usual but only 50ms long was flagged")
	}
}

func TestHistoryUnfinishedRunCountsOnlyWhenSlow(t *testing.T) {
	var h History
	p := mustParse(t, lookup)
	for range minRuns {
		h.Ran("", "a", p, 10*time.Millisecond, true, Tuning{})
		h.Ran("", "b", Plan{Cost: 1, Shape: 1}, time.Second, true, Tuning{})
	}
	before := h.Judge("a", p, Tuning{}).Factor

	quick := h.Ran("", "a", p, 30*time.Millisecond, false, Tuning{})
	timedOut := h.Ran("", "a", p, 30*time.Second, false, Tuning{})

	// A failed run says nothing about the plan's timing, unless it ran far too long first, as a cancelled one does.
	if before == 1 {
		t.Fatal("the plan learned nothing to change")
	}
	if quick || !timedOut || h.Judge("a", p, Tuning{}).Factor != before {
		t.Errorf("quick failure flagged %v, timeout %v, factor %v then %v; want only the timeout flagged and the factor unchanged",
			quick, timedOut, before, h.Judge("a", p, Tuning{}).Factor)
	}
}

func TestHistoryIgnoresRunOfUnknownLength(t *testing.T) {
	var h History
	p := mustParse(t, lookup)
	for range minRuns {
		h.Ran("", "a", p, 10*time.Millisecond, true, Tuning{})
		h.Ran("", "b", Plan{Cost: 1, Shape: 1}, time.Second, true, Tuning{})
	}
	before := h.Judge("a", p, Tuning{}).Factor

	h.Ran("", "a", p, 0, true, Tuning{})

	if after := h.Judge("a", p, Tuning{}).Factor; after != before {
		t.Errorf("factor %v, then %v after a run of unknown length; want it unchanged", before, after)
	}
}

func TestHistoryStaysWithinSize(t *testing.T) {
	h := History{Size: 2}
	for _, key := range []string{"a", "b", "c", "d"} {
		h.Ran("", key, Plan{Cost: 1, Shape: 1}, time.Millisecond, true, Tuning{})
	}
	if n := len(h.statements); n > 2 {
		t.Errorf("history holds %d statements; want at most 2", n)
	}
}

func TestCacheForget(t *testing.T) {
	c := &Cache{RefreshOneIn: -1}
	calls := 0
	explain := func() (Plan, error) { calls++; return Plan{}, nil }
	for _, key := range []string{"shop\x00a", "shop\x00b", "crm\x00a"} {
		c.Get(key, explain)
	}

	c.Forget(func(key string) bool { return strings.HasPrefix(key, "shop\x00") })
	for _, key := range []string{"shop\x00a", "shop\x00b", "crm\x00a"} {
		c.Get(key, explain)
	}

	if calls != 5 {
		t.Errorf("%d explains; want 3, then 2 more for the forgotten plans", calls)
	}
}

func TestCatalogStaleNeverWaitsForAFirstLoad(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		c := &Catalog{load: func(context.Context, string) (map[Table]stats, error) {
			<-release
			return map[Table]stats{{"public", "t"}: {rows: 10, modified: 1000}}, nil
		}}

		// It answers while a session waits on it, so it reports nothing until the sizes arrive.
		early := c.Stale("shop", Table{"public", "t"})
		close(release)
		synctest.Wait()
		late := c.Stale("shop", Table{"public", "t"})

		if early || !late {
			t.Errorf("Stale = %v before the first load and %v after; want false, then true", early, late)
		}
	})
}

func TestCatalogStaleTables(t *testing.T) {
	c := &Catalog{load: func(context.Context, string) (map[Table]stats, error) {
		return map[Table]stats{
			{"public", "fresh"}:   {rows: 10_000, modified: 1000},
			{"public", "stale"}:   {rows: 10_000, modified: 5000},
			{"public", "new"}:     {rows: -1, modified: 100},
			{"public", "unused"}:  {rows: -1},
			{"public", "smaller"}: {rows: 10, modified: 40},
		}, nil
	}}
	// Rows waits for the first load, which Stale doesn't.
	c.Rows("shop", Table{"public", "fresh"})
	got := map[string]bool{}
	for _, name := range []string{"fresh", "stale", "new", "unused", "smaller", "missing"} {
		got[name] = c.Stale("shop", Table{"public", name})
	}
	want := map[string]bool{"stale": true, "new": true}
	for name := range got {
		if got[name] != want[name] {
			t.Errorf("Stale = %v; want %v", got, want)
			break
		}
	}
	if _, ok := c.Rows("shop", Table{"public", "new"}); ok {
		t.Error("a table never analyzed has a size")
	}
}

func TestMonitorReportsEachInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := &Monitor{read: func(context.Context, []Table) (Activity, error) {
			return Activity{Waiting: map[int32]Wait{7: {Blockers: []int32{3}}}}, nil
		}}
		var reports atomic.Int32
		go m.Run(t.Context(), func(a Activity) {
			if a.LockWaits() == 1 {
				reports.Add(1)
			}
		})

		time.Sleep(3*DefaultMonitorInterval + time.Millisecond)

		if n := reports.Load(); n != 3 {
			t.Errorf("%d reports of one lock wait in 3 intervals; want 3", n)
		}
	})
}

func TestMonitorTurnsFinishedLockWaitTimeIntoARate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// pg_stat_lock's wait_time grows by the milliseconds of each lock wait that ended, so 2s more in 1s is two sessions waiting.
		totals := []float64{100, 600, 2600}
		var polls atomic.Int32
		m := &Monitor{read: func(context.Context, []Table) (Activity, error) {
			return Activity{finishedWaitMS: totals[min(int(polls.Add(1)), len(totals))-1]}, nil
		}}
		var mu sync.Mutex
		var got []int
		go m.Run(t.Context(), func(a Activity) {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, a.LockWaits())
		})

		time.Sleep(3*DefaultMonitorInterval + time.Millisecond)

		mu.Lock()
		defer mu.Unlock()
		if !slices.Equal(got, []int{0, 1, 2}) {
			t.Errorf("lock waits %v; want 0 with nothing to compare, then 1 (0.5 rounded), then 2", got)
		}
	})
}

func TestMonitorSkipsFailedReads(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var polls atomic.Int32
		m := &Monitor{Log: slog.New(slog.DiscardHandler), read: func(context.Context, []Table) (Activity, error) {
			if polls.Add(1) == 1 {
				return Activity{}, errors.New("connection refused")
			}
			return Activity{ReplicationLag: time.Second}, nil
		}}
		var reports []Activity
		var mu sync.Mutex
		go m.Run(t.Context(), func(a Activity) {
			mu.Lock()
			defer mu.Unlock()
			reports = append(reports, a)
		})

		time.Sleep(2*DefaultMonitorInterval + time.Millisecond)

		mu.Lock()
		defer mu.Unlock()
		if len(reports) != 1 || reports[0].ReplicationLag != time.Second {
			t.Errorf("reports %+v; want only the one read that worked", reports)
		}
	})
}

func TestMonitorReportsNothingKnownOnceReadsKeepFailing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var polls atomic.Int32
		m := &Monitor{Log: slog.New(slog.DiscardHandler), read: func(context.Context, []Table) (Activity, error) {
			if polls.Add(1) == 1 {
				return Activity{Waiting: map[int32]Wait{7: {Blockers: []int32{3}}}, ReplicationLag: time.Minute}, nil
			}
			return Activity{}, errors.New("connection refused")
		}}
		var reports []Activity
		var mu sync.Mutex
		go m.Run(t.Context(), func(a Activity) {
			mu.Lock()
			defer mu.Unlock()
			reports = append(reports, a)
		})

		time.Sleep((1+staleReads)*DefaultMonitorInterval + time.Millisecond)

		mu.Lock()
		defer mu.Unlock()
		// Holds and limits set from the last reading would otherwise stay for as long as the reads fail.
		if len(reports) != 2 || reports[1].LockWaits() != 0 || reports[1].ReplicationLag != 0 {
			t.Errorf("reports %+v; want the reading, then nothing known after %d failed reads", reports, staleReads)
		}
	})
}

func TestMonitorReadsTheWatchedTables(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		jobs := Table{"public", "jobs"}
		var asked atomic.Pointer[[]Table]
		m := &Monitor{Watch: func() []Table { return []Table{jobs} }, read: func(_ context.Context, watch []Table) (Activity, error) {
			asked.Store(&watch)
			return Activity{}, nil
		}}
		go m.Run(t.Context(), func(Activity) {})

		time.Sleep(DefaultMonitorInterval + time.Millisecond)

		if got := asked.Load(); got == nil || !slices.Equal(*got, []Table{jobs}) {
			t.Errorf("read asked for %v; want the watched tables", got)
		}
	})
}

func TestHistoryKeepsTheTimingOfBoundedTenants(t *testing.T) {
	var h History
	for i := range maxTenants + 10 {
		h.Ran(strconv.Itoa(i), "s", Plan{Cost: 1000, Shape: 1}, 100*time.Millisecond, true, Tuning{})
	}

	if n := len(h.tenants); n > maxTenants {
		t.Errorf("History keeps %d tenants' timing; want at most %d", n, maxTenants)
	}
}
