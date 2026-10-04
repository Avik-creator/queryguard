// Package plan reads Postgres's EXPLAIN output, caches plans by statement, learns how plans run and keeps table sizes from the catalog.
package plan

import (
	"cmp"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"maps"
	"math"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Defaults used when the matching field is zero.
const (
	DefaultTTL             = time.Minute
	DefaultRefreshOneIn    = 100
	DefaultSize            = 10_000
	DefaultCatalogInterval = time.Minute
	DefaultCredibility     = 10
	DefaultQuarantine      = 10 * time.Minute
)

// How History learns: a plan's timing averages its last runs, and the server's its last many more.
const (
	minRuns      = 5    // runs of a plan before a change from it, or a run far slower than it, is flagged
	planWindow   = 50   // runs a plan's timing is averaged over
	globalWindow = 1000 // runs the server's timing is averaged over
	maxFactor    = 100  // the most a statement's timing moves its cost either way
	maxShapes    = 8    // plans remembered for each statement
	slowRatio    = 10   // a run this many times slower than its plan's usual timing is flagged
	// slowFloor is the shortest run flagged as slow: under load a quick statement now and then takes tens of milliseconds.
	slowFloor = 100 * time.Millisecond
	// learnFloor is the shortest run costs are learned from: a quicker one is mostly the round trip and the work every
	// statement does, which would make long plans look cheap per cost unit next to it.
	learnFloor = 5 * time.Millisecond
)

// A table is stale when more of it has changed since it was last analyzed than twice what makes autovacuum analyze it by default.
const (
	staleRows  = 50  // twice autovacuum_analyze_threshold's default would be 100; changes to tiny tables matter less
	staleShare = 0.2 // twice autovacuum_analyze_scale_factor's default
)

// catalogTimeout bounds one load of table sizes, so a slow catalog can't hold up the statement waiting for it.
const catalogTimeout = 5 * time.Second

// Plan is what the cost rules and History need from one EXPLAIN.
type Plan struct {
	Cost     float64 // the planner's estimate for the whole statement, in its cost units, over every query it rewrites into
	SeqScans []Table // tables read in full, each listed once
	Indexed  []Table // tables read through an index, each listed once
	Shape    uint64  // a hash of what the plan does and to which tables and indexes, without its estimates
}

// Table names a table as EXPLAIN VERBOSE and pg_class do.
type Table struct{ Schema, Name string }

func (t Table) String() string { return t.Schema + "." + t.Name }

// node is one plan node of EXPLAIN (FORMAT JSON, VERBOSE); the rest of its fields are ignored.
type node struct {
	Type     string   `json:"Node Type"`
	Strategy string   `json:"Strategy"`
	Join     string   `json:"Join Type"`
	Parent   string   `json:"Parent Relationship"`
	Partial  string   `json:"Partial Mode"`
	Parallel bool     `json:"Parallel Aware"`
	Schema   string   `json:"Schema"`
	Relation string   `json:"Relation Name"`
	Index    string   `json:"Index Name"`
	Cost     *float64 `json:"Total Cost"`
	Plans    []node   `json:"Plans"`
}

// indexScans read a table through an index; a Bitmap Heap Scan names the table and its Bitmap Index Scan the index.
var indexScans = []string{"Index Scan", "Index Only Scan", "Bitmap Heap Scan"}

// Parse reads the output of EXPLAIN (FORMAT JSON, VERBOSE).
func Parse(out string) (Plan, error) {
	var explained []struct {
		Plan *node `json:"Plan"`
	}
	if err := json.Unmarshal([]byte(out), &explained); err != nil {
		return Plan{}, err
	}
	var p Plan
	shape := fnv.New64a()
	var walk func(n *node)
	walk = func(n *node) {
		t := Table{n.Schema, n.Relation}
		switch {
		// A parallel scan is a Seq Scan node too, under a Gather.
		case n.Type == "Seq Scan" && !slices.Contains(p.SeqScans, t):
			p.SeqScans = append(p.SeqScans, t)
		case slices.Contains(indexScans, n.Type) && !slices.Contains(p.Indexed, t):
			p.Indexed = append(p.Indexed, t)
		}
		fmt.Fprintf(shape, "(%q %q %q %q %q %t %q %q", n.Type, n.Strategy, n.Join, n.Parent, n.Partial, n.Parallel, t, n.Index)
		for i := range n.Plans {
			walk(&n.Plans[i])
		}
		shape.Write([]byte{')'})
	}
	// Rules can rewrite a statement into several queries, each with its own plan, or into none.
	for _, e := range explained {
		if e.Plan == nil || e.Plan.Cost == nil {
			return Plan{}, errors.New("EXPLAIN output has a query without a plan and its total cost")
		}
		p.Cost += *e.Plan.Cost
		walk(e.Plan)
	}
	p.Shape = shape.Sum64()
	return p, nil
}

// Cache keeps plans by key for TTL, so a statement seen recently isn't explained again; it is safe for concurrent use.
type Cache struct {
	TTL          time.Duration // how long a plan is used before the statement is explained again; 0 means DefaultTTL
	Size         int           // the most plans kept; 0 means DefaultSize
	RefreshOneIn int           // explain about one hit in this many again, catching plans that change early; 0 means DefaultRefreshOneIn, negative never

	mu      sync.Mutex
	entries map[string]entry
	stats   Stats
}

type entry struct {
	plan    Plan
	expires time.Time
}

// Stats counts the cache's work since it was made.
type Stats struct {
	Hits, Misses int64         // a miss is a statement explained
	Explaining   time.Duration // the time misses spent explaining, which is what the cost check adds to queries
	Slowest      time.Duration // the longest single explain
}

// Get returns the plan stored under key, or calls explain and stores its plan; a failed explain is not stored.
func (c *Cache) Get(key string, explain func() (Plan, error)) (Plan, error) {
	c.mu.Lock()
	e, ok := c.entries[key]
	// Explaining a small share of hits again catches a plan that changed before its entry expires.
	if ok && time.Now().Before(e.expires) && !c.refreshNow() {
		c.stats.Hits++
		c.mu.Unlock()
		return e.plan, nil
	}
	c.mu.Unlock()

	// Two sessions missing the same key both explain it; holding the lock across a round trip would stall every session.
	start := time.Now()
	p, err := explain()
	took := time.Since(start)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.Misses++
	c.stats.Explaining += took
	c.stats.Slowest = max(c.stats.Slowest, took)
	if err != nil {
		return Plan{}, err
	}
	if c.entries == nil {
		c.entries = map[string]entry{}
	}
	if len(c.entries) >= cmp.Or(c.Size, DefaultSize) {
		c.evict()
	}
	c.entries[key] = entry{p, time.Now().Add(cmp.Or(c.TTL, DefaultTTL))}
	return p, nil
}

// refreshNow says whether to explain a cached statement again.
func (c *Cache) refreshNow() bool {
	return c.RefreshOneIn >= 0 && rand.N(cmp.Or(c.RefreshOneIn, DefaultRefreshOneIn)) == 0
}

// evict drops expired plans, or, when none has expired, an arbitrary one; the caller holds mu.
func (c *Cache) evict() {
	now := time.Now()
	for key, e := range c.entries {
		if now.After(e.expires) {
			delete(c.entries, key)
		}
	}
	for key := range c.entries {
		if len(c.entries) < cmp.Or(c.Size, DefaultSize) {
			return
		}
		delete(c.entries, key)
	}
}

// Forget drops the plans whose keys match, so their statements are explained again.
func (c *Cache) Forget(match func(key string) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	maps.DeleteFunc(c.entries, func(key string, _ entry) bool { return match(key) })
}

// Stats returns the counts so far.
func (c *Cache) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// History learns, for each statement, which plan it usually gets and how long each of its plans takes; it is safe for concurrent use.
type History struct {
	Size int // statements remembered; 0 means DefaultSize

	mu         sync.Mutex
	statements map[string]*statement
	server     timing // finished runs long enough to learn from, so a plan's timing is judged against the server's
}

// Tuning sets how History judges; it comes with each call, so a reloaded config applies at once.
type Tuning struct {
	Credibility float64       // runs a plan needs before its own timing counts as much as the server's; 0 means DefaultCredibility
	Quarantine  time.Duration // the half-life of past runs, so a new plan is taken as the usual one after about this long; 0 means DefaultQuarantine
}

// Verdict is what History makes of a statement about to run with a plan.
type Verdict struct {
	Factor float64 // what the plan's cost is multiplied by to match how long it runs here, next to the server's other plans
	Flip   string  // why the plan looks like a regression from the statement's usual one, or ""
	First  bool    // the flip is new, so worth logging
}

// statement is what History knows about one statement, by plan shape.
type statement struct {
	shapes map[uint64]*shape
	used   time.Time
}

// shape is one plan of a statement.
type shape struct {
	seqScans, indexed []Table
	runs              int     // every finished run
	weight            float64 // runs, each fading with Tuning.Quarantine as half-life
	updated           time.Time
	logRatio          float64 // the mean of ln(seconds ÷ cost) over about planWindow runs, to tell a slow run
	samples           int
	costRatio         float64 // the same over runs long enough to learn costs from
	costSamples       int
	slow              bool // its last run took far longer than its timing predicts, as when Postgres runs a generic plan instead
	flagged           bool // a flip of this plan was reported, so it isn't reported again until the flip ends
	firstSeen         time.Time
	chosen            time.Time // when it was last about to run
}

// timing averages ln(seconds ÷ cost) over runs weighted by their cost, so a cheap statement's long lock wait counts for little.
type timing struct {
	logRatio, cost float64 // averages of cost × ln(seconds ÷ cost) and of cost
	runs           int
}

// Judge returns what History makes of key about to run with p.
func (h *History) Judge(key string, p Plan, t Tuning) Verdict {
	h.mu.Lock()
	defer h.mu.Unlock()
	v := Verdict{Factor: 1}
	st := h.statements[key]
	if st == nil {
		return v
	}
	st.used = time.Now()
	sh := st.shape(p, t)
	v.Factor = h.factor(sh, t)
	switch usual := st.usual(t); {
	case sh.slow:
		v.Flip = fmt.Sprintf("its last run was over %d times slower than its plan's usual timing", slowRatio)
	// A plan that keeps running beside the usual one is the plan for other values, as for a common value in skewed data.
	case usual != nil && usual != sh && !(sh.runs >= minRuns && usual.chosen.After(sh.firstSeen)):
		v.Flip = regression(usual, p)
	}
	sh.chosen = time.Now()
	v.First = v.Flip != "" && !sh.flagged
	sh.flagged = v.Flip != ""
	return v
}

// Ran records that key ran with p for took, finished or not, and reports whether that run made p slow: far slower than it usually runs,
// when the run before wasn't. A took of 0 is unknown.
func (h *History) Ran(key string, p Plan, took time.Duration, finished bool, t Tuning) (turnedSlow bool) {
	if took <= 0 {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.statement(key)
	sh := st.shape(p, t)
	ratio := math.Log(took.Seconds() / max(p.Cost, 1))
	// A failed run says nothing about its plan's timing, unless it ran far too long first, as a cancelled one may.
	slow := sh.samples >= minRuns && took >= slowFloor && ratio-sh.logRatio >= math.Log(slowRatio)
	turnedSlow = slow && !sh.slow
	if !finished {
		sh.slow = sh.slow || slow
		return turnedSlow
	}
	sh.slow = slow
	sh.runs++
	sh.weight++
	sh.samples++
	sh.logRatio += (ratio - sh.logRatio) / float64(min(sh.samples, planWindow))
	if took >= learnFloor {
		sh.costSamples++
		sh.costRatio += (ratio - sh.costRatio) / float64(min(sh.costSamples, planWindow))
		h.server.add(ratio, max(p.Cost, 1))
	}
	return turnedSlow
}

// factor blends sh's timing with the server's by credibility n/(n+m), as Bühlmann's formula does; the caller holds mu.
func (h *History) factor(sh *shape, t Tuning) float64 {
	if h.server.runs == 0 || sh.costSamples == 0 {
		return 1
	}
	z := float64(sh.costSamples) / (float64(sh.costSamples) + cmp.Or(t.Credibility, DefaultCredibility))
	f := math.Exp(z * (sh.costRatio - h.server.logRatio/h.server.cost))
	return min(max(f, 1.0/maxFactor), maxFactor)
}

// statement returns key's record, making it, and room for it, when new; the caller holds mu.
func (h *History) statement(key string) *statement {
	if h.statements == nil {
		h.statements = map[string]*statement{}
	}
	st := h.statements[key]
	if st == nil {
		if len(h.statements) >= cmp.Or(h.Size, DefaultSize) {
			// The statement least recently seen goes.
			var oldest string
			for k, s := range h.statements {
				if oldest == "" || s.used.Before(h.statements[oldest].used) {
					oldest = k
				}
			}
			delete(h.statements, oldest)
		}
		st = &statement{shapes: map[uint64]*shape{}}
		h.statements[key] = st
	}
	st.used = time.Now()
	return st
}

// shape returns p's record with its runs faded to now, making it when new.
func (st *statement) shape(p Plan, t Tuning) *shape {
	st.fade(t)
	sh := st.shapes[p.Shape]
	if sh == nil {
		if len(st.shapes) >= maxShapes {
			// The plan run least lately goes.
			delete(st.shapes, slices.MinFunc(slices.Collect(maps.Keys(st.shapes)), func(a, b uint64) int {
				return cmp.Compare(st.shapes[a].weight, st.shapes[b].weight)
			}))
		}
		sh = &shape{seqScans: p.SeqScans, indexed: p.Indexed, updated: time.Now(), firstSeen: time.Now()}
		st.shapes[p.Shape] = sh
	}
	return sh
}

// fade brings every plan's weight to now.
func (st *statement) fade(t Tuning) {
	now := time.Now()
	for _, sh := range st.shapes {
		sh.weight *= math.Exp2(-now.Sub(sh.updated).Seconds() / cmp.Or(t.Quarantine, DefaultQuarantine).Seconds())
		sh.updated = now
	}
}

// usual returns the plan with the most recent runs, among those run often enough to judge others by, or nil.
func (st *statement) usual(t Tuning) *shape {
	st.fade(t)
	var best *shape
	for _, sh := range st.shapes {
		if sh.runs >= minRuns && (best == nil || sh.weight > best.weight) {
			best = sh
		}
	}
	return best
}

// regression says how p does worse than the usual plan, or returns "".
func regression(usual *shape, p Plan) string {
	for _, t := range p.SeqScans {
		if slices.Contains(usual.indexed, t) && !slices.Contains(usual.seqScans, t) {
			return "it reads " + t.String() + " in full where the statement's usual plan uses an index"
		}
	}
	return ""
}

// add counts one run, averaging over about globalWindow runs.
func (g *timing) add(logRatio, cost float64) {
	g.runs++
	w := float64(min(g.runs, globalWindow))
	g.logRatio += (cost*logRatio - g.logRatio) / w
	g.cost += (cost - g.cost) / w
}

// Catalog knows the row count of every table, and how much of it changed since it was analyzed, over its own connection to each database.
type Catalog struct {
	DSN      string        // connection string for a role that can read pg_class; the database is set per lookup
	Interval time.Duration // how often sizes are read again; 0 means DefaultCatalogInterval
	Log      *slog.Logger  // nil means slog.Default()

	// load reads one database's table sizes; nil reads them from Postgres at DSN.
	load func(ctx context.Context, database string) (map[Table]stats, error)

	mu        sync.Mutex
	databases map[string]*sizes
}

// stats are one table's planner statistics.
type stats struct {
	rows     float64 // pg_class.reltuples, -1 until the table is first analyzed
	modified float64 // n_mod_since_analyze: rows inserted, updated or deleted since
}

// sizes are one database's table sizes.
type sizes struct {
	first     func() // loads the sizes on the first call only
	mu        sync.Mutex
	tables    map[Table]stats
	loaded    time.Time
	reloading bool
}

// Rows returns t's row count in database, or false when unknown; the first lookup waits, later ones reload stale sizes in the background.
func (c *Catalog) Rows(database string, t Table) (float64, bool) {
	st, ok := c.lookup(database, t, true)
	return st.rows, ok && st.rows >= 0
}

// Stale reports whether so much of t changed since it was last analyzed that the planner's estimates for it may be far off;
// it never waits for the first load, which it starts, and says false until then.
func (c *Catalog) Stale(database string, t Table) bool {
	st, ok := c.lookup(database, t, false)
	return ok && st.modified > staleRows+staleShare*max(st.rows, 0)
}

// lookup returns t's statistics in database, as Rows describes, waiting for the first load only if wait is set.
func (c *Catalog) lookup(database string, t Table, wait bool) (stats, bool) {
	c.mu.Lock()
	if c.databases == nil {
		c.databases = map[string]*sizes{}
	}
	s, ok := c.databases[database]
	if !ok {
		s = &sizes{}
		s.first = sync.OnceFunc(func() { c.reload(database, s) })
		c.databases[database] = s
	}
	c.mu.Unlock()

	if wait {
		s.first()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loaded.IsZero() {
		// Only a lookup that doesn't wait gets here before the first load has ended.
		go s.first()
		return stats{}, false
	}
	if !s.reloading && time.Since(s.loaded) > cmp.Or(c.Interval, DefaultCatalogInterval) {
		s.reloading = true
		go c.reload(database, s)
	}
	st, ok := s.tables[t]
	return st, ok
}

// reload reads database's sizes again, keeping the old ones when that fails.
func (c *Catalog) reload(database string, s *sizes) {
	ctx, cancel := context.WithTimeout(context.Background(), catalogTimeout)
	defer cancel()
	load := c.load
	if load == nil {
		load = c.query
	}
	tables, err := load(ctx, database)
	if err != nil {
		cmp.Or(c.Log, slog.Default()).Warn("read table sizes", "database", database, "err", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// A failed load is retried after the interval too, rather than on every statement.
	s.loaded, s.reloading = time.Now(), false
	if err == nil {
		s.tables = tables
	}
}

// query reads every table's row count in database from pg_class, and its changes since it was analyzed from pg_stat_all_tables.
func (c *Catalog) query(ctx context.Context, database string) (map[Table]stats, error) {
	cfg, err := pgx.ParseConfig(c.DSN)
	if err != nil {
		return nil, err
	}
	cfg.Database = database
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.Background())

	// reltuples is -1 until a table is first analyzed; partitioned tables count their rows, and their changes, in each partition.
	rows, err := conn.Query(ctx, `select n.nspname, c.relname, c.reltuples, coalesce(s.n_mod_since_analyze, 0)::float8 from pg_class c
		join pg_namespace n on n.oid = c.relnamespace left join pg_stat_all_tables s on s.relid = c.oid
		where c.relkind in ('r', 'm')`)
	if err != nil {
		return nil, err
	}
	tables := map[Table]stats{}
	var t Table
	var st stats
	_, err = pgx.ForEachRow(rows, []any{&t.Schema, &t.Name, &st.rows, &st.modified}, func() error {
		tables[t] = st
		return nil
	})
	return tables, err
}
