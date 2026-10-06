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

	"github.com/Avik-creator/queryguard/internal/safe"
	"github.com/Avik-creator/queryguard/pkg/stats"
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
	minRuns      = 5                // runs of a plan before a change from it, or a run far slower than it, is flagged
	planWindow   = 50               // runs a plan's timing is averaged over
	settleTime   = 10 * time.Minute // about how long a plan runs at a new speed before that is its settled timing
	globalWindow = 1000             // runs a tenant's timing is averaged over
	// tenantRuns is how many runs a tenant's timing needs to count fully in the server's; past it, no tenant counts more than another.
	tenantRuns = 100
	// tenantCost is the mean plan cost at which a tenant's runs count fully in the server's timing: a cheap statement's time is
	// mostly waiting and the round trip, but a costlier one's counts no more, so one plan of huge cost can't set it for all.
	tenantCost = 1000
	maxTenants = 1000 // tenants whose timing is kept; the one least recently run goes first
	maxFactor  = 100  // the most a statement's timing moves its cost either way
	maxShapes  = 8    // plans remembered for each statement
	slowRatio  = 10   // a run this many times slower than its plan's usual timing is flagged
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
	tenants    map[string]*timing // each tenant's finished runs long enough to learn from; together they are the server's timing
}

// Tuning sets how History judges; it comes with each call, so a reloaded config applies at once.
type Tuning struct {
	Credibility float64       // runs a plan needs before its own timing counts as much as the server's; 0 means DefaultCredibility
	Quarantine  time.Duration // the half-life of past runs, so a new plan is taken as the usual one after about this long; 0 means DefaultQuarantine
}

// Verdict is what History makes of a statement about to run with a plan.
type Verdict struct {
	Factor float64       // what the plan's cost is multiplied by to match how long it runs here, next to the server's other plans
	Flip   string        // why the plan looks like a regression from the statement's usual one, or ""
	First  bool          // the flip is new, so worth logging
	Usual  time.Duration // how long the plan usually runs, once it has run often enough to say; else 0
	// Settled is Usual over minutes rather than runs, so overload, which fills planWindow in seconds, still shows as overload.
	Settled time.Duration
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
	settled           float64 // logRatio averaged over about settleTime, once planWindow runs have filled it
	settledAt         time.Time
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
	used           time.Time
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
	if sh.samples >= minRuns {
		v.Usual = time.Duration(math.Exp(sh.logRatio) * max(p.Cost, 1) * float64(time.Second))
		v.Settled = time.Duration(math.Exp(sh.settled) * max(p.Cost, 1) * float64(time.Second))
	}
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

// Ran records that key ran for tenant with p for took, finished or not, and reports whether that run made p slow: far slower than
// it usually runs, when the run before wasn't. A took of 0 is unknown.
func (h *History) Ran(tenant, key string, p Plan, took time.Duration, finished bool, t Tuning) (turnedSlow bool) {
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
	if now := time.Now(); sh.samples <= planWindow {
		sh.settled, sh.settledAt = sh.logRatio, now
	} else {
		sh.settled += (sh.logRatio - sh.settled) * -math.Expm1(-now.Sub(sh.settledAt).Seconds()/settleTime.Seconds())
		sh.settledAt = now
	}
	if took >= learnFloor {
		sh.costSamples++
		sh.costRatio += (ratio - sh.costRatio) / float64(min(sh.costSamples, planWindow))
		h.tenant(tenant).add(ratio, max(p.Cost, 1))
	}
	return turnedSlow
}

// factor blends sh's timing with the server's by credibility n/(n+m), as Bühlmann's formula does; the caller holds mu.
func (h *History) factor(sh *shape, t Tuning) float64 {
	server, ok := h.server()
	if !ok || sh.costSamples == 0 {
		return 1
	}
	z := float64(sh.costSamples) / (float64(sh.costSamples) + cmp.Or(t.Credibility, DefaultCredibility))
	f := math.Exp(z * (sh.costRatio - server))
	return min(max(f, 1.0/maxFactor), maxFactor)
}

// server returns the server's mean ln(seconds ÷ cost), each tenant's weighing by its runs up to tenantRuns, so one busy tenant
// can't drag every other tenant's costs and charges toward its own, times its mean cost over tenantCost up to 1, so a cheap
// statement's long wait counts for little across tenants too; false before any run; the caller holds mu.
func (h *History) server() (float64, bool) {
	var sum, weight float64
	for _, g := range h.tenants {
		w := float64(min(g.runs, tenantRuns)) * min(g.cost, tenantCost)
		sum += w * g.logRatio / g.cost
		weight += w
	}
	if weight == 0 {
		return 0, false
	}
	return sum / weight, true
}

// tenant returns tenant's timing, making it, and room for it, when new; the caller holds mu.
func (h *History) tenant(tenant string) *timing {
	if h.tenants == nil {
		h.tenants = map[string]*timing{}
	}
	g := h.tenants[tenant]
	if g == nil {
		if len(h.tenants) >= maxTenants {
			var oldest string
			for k, o := range h.tenants {
				if oldest == "" || o.used.Before(h.tenants[oldest].used) {
					oldest = k
				}
			}
			delete(h.tenants, oldest)
		}
		g = &timing{}
		h.tenants[tenant] = g
	}
	g.used = time.Now()
	return g
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
	load func(ctx context.Context, database string) (map[Table]tableStats, error)

	mu        sync.Mutex
	databases map[string]*sizes
}

// tableStats are one table's planner statistics.
type tableStats struct {
	rows     float64 // pg_class.reltuples, -1 until the table is first analyzed
	modified float64 // n_mod_since_analyze: rows inserted, updated or deleted since
}

// sizes are one database's table sizes.
type sizes struct {
	first     func() // loads the sizes on the first call only
	mu        sync.Mutex
	tables    map[Table]tableStats
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
func (c *Catalog) lookup(database string, t Table, wait bool) (tableStats, bool) {
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
		return tableStats{}, false
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
	// A panic in the load is a failed load, so the statements waiting on it go on without sizes.
	tables, err := func() (_ map[Table]tableStats, err error) {
		defer safe.Recover(func(p error) { err = p })
		return load(ctx, database)
	}()
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
func (c *Catalog) query(ctx context.Context, database string) (map[Table]tableStats, error) {
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
	tables := map[Table]tableStats{}
	var t Table
	var st tableStats
	_, err = pgx.ForEachRow(rows, []any{&t.Schema, &t.Name, &st.rows, &st.modified}, func() error {
		tables[t] = st
		return nil
	})
	return tables, err
}

// DefaultMonitorInterval is how often a Monitor reads the server's activity when its Interval is zero.
const DefaultMonitorInterval = time.Second

// DefaultStatementsInterval is how often a Monitor reads pg_stat_statements when its StatementsEvery is zero; it can hold thousands of rows.
const DefaultStatementsInterval = 10 * time.Second

// Monitor reads what the whole server is doing over its own connection, for signals no single session sees.
type Monitor struct {
	DSN      string         // connection string for a role in pg_monitor; watched tables are in its database
	Interval time.Duration  // how often it reads; 0 means DefaultMonitorInterval
	Watch    func() []Table // tables whose dead tuples are reported; nil watches none
	Log      *slog.Logger   // nil means slog.Default()
	// StatementsEvery is how often pg_stat_statements is read, when installed in DSN's database; 0 means DefaultStatementsInterval.
	StatementsEvery time.Duration

	// read reads the activity once; nil reads it from Postgres at DSN.
	read func(ctx context.Context, watch []Table) (Activity, error)
	// readStatements reads pg_stat_statements once, nil when it isn't installed; nil reads it from Postgres at DSN.
	readStatements func(ctx context.Context) ([]stats.Counters, error)
}

// Activity is what the server was doing at one reading.
type Activity struct {
	Waiting        map[int32]Wait    // backends waiting on a lock, by process ID
	ReplicationLag time.Duration     // the most any standby lags in replaying; 0 without standbys
	Horizon        Snapshot          // the backend holding back the MVCC horizon most; PID 0 when none
	DeadTuples     map[Table]float64 // of the watched tables
	FinishedWaits  float64           // sessions that waited on locks, on average, in waits that ended since the last reading (PG19)
	Statements     []stats.Counters  // pg_stat_statements' entries, at the readings that read them; nil at the others
	finishedWaitMS float64           // pg_stat_lock's total wait_time, in milliseconds
}

// Wait is one backend's wait for a lock.
type Wait struct {
	Blockers []int32       // the backends it waits for, from pg_blocking_pids
	Waited   time.Duration // since it started waiting; 0 when Postgres hasn't said yet
}

// Snapshot is a backend's oldest snapshot.
type Snapshot struct {
	PID int32
	Age time.Duration // since its transaction, or else its statement, started
}

// LockWaits is how many sessions wait on locks: those waiting now, or more when more waited since the last reading.
func (a Activity) LockWaits() int { return max(len(a.Waiting), int(math.Round(a.FinishedWaits))) }

// staleReads is how many reads in a row may fail before the Monitor reports that it knows nothing of the server.
const staleReads = 3

// Run reads the activity every Interval and passes each reading to report, until ctx ends; a failed reading is logged and
// skipped, and after staleReads of them in a row an empty Activity is reported.
func (m *Monitor) Run(ctx context.Context, report func(Activity)) {
	var r activityReader
	defer r.close()
	read, readStatements := m.read, m.readStatements
	if read == nil {
		read = func(ctx context.Context, watch []Table) (Activity, error) { return r.read(ctx, m.DSN, watch) }
	}
	if readStatements == nil {
		readStatements = func(ctx context.Context) ([]stats.Counters, error) { return r.statements(ctx, m.DSN) }
	}
	var last Activity
	var lastAt time.Time
	failed := 0
	statementsAt, statementsErr := time.Now(), ""
	tick := time.Tick(cmp.Or(m.Interval, DefaultMonitorInterval))
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
		var watch []Table
		if m.Watch != nil {
			watch = m.Watch()
		}
		rctx, cancel := context.WithTimeout(ctx, catalogTimeout)
		a, err := read(rctx, watch)
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				cmp.Or(m.Log, slog.Default()).Warn("read server activity", "err", err)
			}
			if failed++; failed == staleReads {
				// What the last reading set, such as a hold while a standby lagged, mustn't outlast it for good.
				last, lastAt = Activity{}, time.Time{}
				report(Activity{})
			}
			continue
		}
		failed = 0
		// Lock wait time counts only once a wait ends, so its growth over a second is how many sessions waited on average.
		switch elapsed := time.Since(lastAt); {
		case lastAt.IsZero() || a.finishedWaitMS < last.finishedWaitMS:
			last, lastAt = a, time.Now()
		case elapsed >= cmp.Or(m.Interval, DefaultMonitorInterval)/2:
			a.FinishedWaits = (a.finishedWaitMS - last.finishedWaitMS) / (elapsed.Seconds() * 1000)
			last, lastAt = a, time.Now()
		default:
			// A reading just after the last, as when a slow one left a tick waiting, is too soon to give a rate of its own.
			a.FinishedWaits = last.FinishedWaits
		}
		if time.Since(statementsAt) >= cmp.Or(m.StatementsEvery, DefaultStatementsInterval) {
			statementsAt = time.Now()
			rctx, cancel := context.WithTimeout(ctx, catalogTimeout)
			cs, err := readStatements(rctx)
			cancel()
			switch {
			case err != nil:
				// A server without pg_stat_statements in shared_preload_libraries fails every read, so the same error is logged once.
				if err.Error() != statementsErr && ctx.Err() == nil {
					cmp.Or(m.Log, slog.Default()).Warn("read pg_stat_statements", "err", err)
				}
				statementsErr = err.Error()
			default:
				statementsErr = ""
				// An empty reading still says what pg_stat_statements no longer has.
				a.Statements = cs
				if cs == nil {
					a.Statements = []stats.Counters{}
				}
			}
		}
		report(a)
	}
}

// activityReader reads the activity over one connection, opened on first use and again after a failure.
type activityReader struct {
	conn    *pgx.Conn
	version int    // server_version_num
	pgss    string // the schema of pg_stat_statements, once found
}

// pg19 is the first server_version_num with pg_stat_lock.
const pg19 = 190000

func (r *activityReader) read(ctx context.Context, dsn string, watch []Table) (Activity, error) {
	if err := r.connect(ctx, dsn); err != nil {
		return Activity{}, err
	}
	a, err := r.query(ctx, watch)
	if err != nil {
		r.close()
	}
	return a, err
}

// connect opens the connection when there is none.
func (r *activityReader) connect(ctx context.Context, dsn string) error {
	if r.conn != nil {
		return nil
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	if err := conn.QueryRow(ctx, "select current_setting('server_version_num')::int").Scan(&r.version); err != nil {
		conn.Close(context.Background())
		return err
	}
	r.conn = conn
	return nil
}

// statements reads every top-level pg_stat_statements entry whose text the role may see; nil when the extension isn't installed.
func (r *activityReader) statements(ctx context.Context, dsn string) ([]stats.Counters, error) {
	if err := r.connect(ctx, dsn); err != nil {
		return nil, err
	}
	// The view lives in the schema the extension was created in, and is looked for each time until it is.
	if r.pgss == "" {
		err := r.conn.QueryRow(ctx, `select n.nspname from pg_extension e join pg_namespace n on n.oid = e.extnamespace
			where e.extname = 'pg_stat_statements'`).Scan(&r.pgss)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
	}
	// Without pg_read_all_stats, other roles' entries have no text and no query ID.
	rows, err := r.conn.Query(ctx, `select d.datname, u.rolname, s.queryid, s.query, s.calls, s.shared_blks_hit, s.shared_blks_read,
		s.temp_blks_read, s.temp_blks_written, s.wal_bytes::float8
		from `+pgx.Identifier{r.pgss, "pg_stat_statements"}.Sanitize()+` s
		join pg_database d on d.oid = s.dbid join pg_roles u on u.oid = s.userid
		where s.toplevel and s.queryid is not null`)
	if err != nil {
		r.pgss = ""
		return nil, err
	}
	var c stats.Counters
	var out []stats.Counters
	_, err = pgx.ForEachRow(rows, []any{&c.Database, &c.Role, &c.QueryID, &c.Query, &c.Calls, &c.SharedHit, &c.SharedRead,
		&c.TempRead, &c.TempWritten, &c.WALBytes}, func() error {
		out = append(out, c)
		return nil
	})
	if err != nil {
		r.pgss = ""
	}
	return out, err
}

func (r *activityReader) close() {
	if r.conn != nil {
		r.conn.Close(context.Background())
		r.conn = nil
	}
}

// query reads the activity in one round trip.
func (r *activityReader) query(ctx context.Context, watch []Table) (Activity, error) {
	a := Activity{Waiting: map[int32]Wait{}, DeadTuples: map[Table]float64{}}
	var b pgx.Batch
	// waitstart is null for a moment after a wait starts.
	b.Queue(`select a.pid, pg_blocking_pids(a.pid), coalesce((select extract(epoch from clock_timestamp() - min(l.waitstart))
		from pg_locks l where l.pid = a.pid and not l.granted), 0)::float8 from pg_stat_activity a where a.wait_event_type = 'Lock'`).
		Query(func(rows pgx.Rows) error {
			var pid int32
			var w Wait
			var waited float64
			_, err := pgx.ForEachRow(rows, []any{&pid, &w.Blockers, &waited}, func() error {
				w.Waited = time.Duration(waited * float64(time.Second))
				a.Waiting[pid] = w
				w = Wait{}
				return nil
			})
			return err
		})
	b.Queue(`select coalesce(extract(epoch from max(replay_lag)), 0)::float8 from pg_stat_replication`).QueryRow(func(row pgx.Row) error {
		var lag float64
		err := row.Scan(&lag)
		a.ReplicationLag = time.Duration(lag * float64(time.Second))
		return err
	})
	// Its own query's snapshot would always be the newest, but it is left out all the same; of backends with the same xmin,
	// the one whose transaction started first holds it longest.
	b.Queue(`select pid, extract(epoch from clock_timestamp() - coalesce(xact_start, query_start, backend_start))::float8
		from pg_stat_activity where backend_xmin is not null and pid <> pg_backend_pid()
		order by age(backend_xmin) desc, coalesce(xact_start, query_start, backend_start) limit 1`).
		Query(func(rows pgx.Rows) error {
			var age float64
			_, err := pgx.ForEachRow(rows, []any{&a.Horizon.PID, &age}, func() error {
				a.Horizon.Age = time.Duration(age * float64(time.Second))
				return nil
			})
			return err
		})
	if len(watch) > 0 {
		schemas, names := make([]string, len(watch)), make([]string, len(watch))
		for i, t := range watch {
			schemas[i], names[i] = t.Schema, t.Name
		}
		b.Queue(`select s.schemaname, s.relname, s.n_dead_tup::float8 from pg_stat_all_tables s
			join unnest($1::text[], $2::text[]) w(schema, name) on s.schemaname = w.schema and s.relname = w.name`, schemas, names).
			Query(func(rows pgx.Rows) error {
				var t Table
				var dead float64
				_, err := pgx.ForEachRow(rows, []any{&t.Schema, &t.Name, &dead}, func() error {
					a.DeadTuples[t] = dead
					return nil
				})
				return err
			})
	}
	if r.version >= pg19 {
		b.Queue(`select coalesce(sum(wait_time), 0)::float8 from pg_stat_lock`).QueryRow(func(row pgx.Row) error {
			return row.Scan(&a.finishedWaitMS)
		})
	}
	return a, r.conn.SendBatch(ctx, &b).Close()
}

// CostOf returns how many cost units take d on this server, from the timing of the runs History learned from, or false before any.
func (h *History) CostOf(d time.Duration) (float64, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	server, ok := h.server()
	if !ok {
		return 0, false
	}
	return d.Seconds() / math.Exp(server), true
}
