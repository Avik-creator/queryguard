// Package plan reads Postgres's EXPLAIN output, caches plans by statement and keeps table sizes from the catalog.
package plan

import (
	"cmp"
	"context"
	"encoding/json/v2"
	"errors"
	"log/slog"
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
)

// catalogTimeout bounds one load of table sizes, so a slow catalog can't hold up the statement waiting for it.
const catalogTimeout = 5 * time.Second

// Plan is what the cost rules need from one EXPLAIN.
type Plan struct {
	Cost     float64 // the planner's estimate for the whole statement, in its cost units, over every query it rewrites into
	SeqScans []Table // tables read in full, each listed once
}

// Table names a table as EXPLAIN VERBOSE and pg_class do.
type Table struct{ Schema, Name string }

func (t Table) String() string { return t.Schema + "." + t.Name }

// node is one plan node of EXPLAIN (FORMAT JSON, VERBOSE); the rest of its fields are ignored.
type node struct {
	Type     string   `json:"Node Type"`
	Schema   string   `json:"Schema"`
	Relation string   `json:"Relation Name"`
	Cost     *float64 `json:"Total Cost"`
	Plans    []node   `json:"Plans"`
}

// Parse reads the output of EXPLAIN (FORMAT JSON, VERBOSE).
func Parse(out string) (Plan, error) {
	var explained []struct {
		Plan *node `json:"Plan"`
	}
	if err := json.Unmarshal([]byte(out), &explained); err != nil {
		return Plan{}, err
	}
	var p Plan
	var walk func(n *node)
	walk = func(n *node) {
		// A parallel scan is a Seq Scan node too, under a Gather.
		if t := (Table{n.Schema, n.Relation}); n.Type == "Seq Scan" && !slices.Contains(p.SeqScans, t) {
			p.SeqScans = append(p.SeqScans, t)
		}
		for i := range n.Plans {
			walk(&n.Plans[i])
		}
	}
	// Rules can rewrite a statement into several queries, each with its own plan, or into none.
	for _, e := range explained {
		if e.Plan == nil || e.Plan.Cost == nil {
			return Plan{}, errors.New("EXPLAIN output has a query without a plan and its total cost")
		}
		p.Cost += *e.Plan.Cost
		walk(e.Plan)
	}
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

// Stats returns the counts so far.
func (c *Cache) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// Catalog knows the row count of every table, read from pg_class over its own connection to each database.
type Catalog struct {
	DSN      string        // connection string for a role that can read pg_class; the database is set per lookup
	Interval time.Duration // how often sizes are read again; 0 means DefaultCatalogInterval
	Log      *slog.Logger  // nil means slog.Default()

	// load reads one database's table sizes; nil reads them from Postgres at DSN.
	load func(ctx context.Context, database string) (map[Table]float64, error)

	mu        sync.Mutex
	databases map[string]*sizes
}

// sizes are one database's table sizes.
type sizes struct {
	first     func() // loads the sizes on the first call only
	mu        sync.Mutex
	rows      map[Table]float64
	loaded    time.Time
	reloading bool
}

// Rows returns t's row count in database, or false when unknown; the first lookup waits, later ones reload stale sizes in the background.
func (c *Catalog) Rows(database string, t Table) (float64, bool) {
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

	s.first()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.reloading && time.Since(s.loaded) > cmp.Or(c.Interval, DefaultCatalogInterval) {
		s.reloading = true
		go c.reload(database, s)
	}
	rows, ok := s.rows[t]
	return rows, ok
}

// reload reads database's sizes again, keeping the old ones when that fails.
func (c *Catalog) reload(database string, s *sizes) {
	ctx, cancel := context.WithTimeout(context.Background(), catalogTimeout)
	defer cancel()
	load := c.load
	if load == nil {
		load = c.query
	}
	rows, err := load(ctx, database)
	if err != nil {
		cmp.Or(c.Log, slog.Default()).Warn("read table sizes", "database", database, "err", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// A failed load is retried after the interval too, rather than on every statement.
	s.loaded, s.reloading = time.Now(), false
	if err == nil {
		s.rows = rows
	}
}

// query reads every analyzed table's row count in database from pg_class.
func (c *Catalog) query(ctx context.Context, database string) (map[Table]float64, error) {
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

	// reltuples is -1 until a table is first analyzed; partitioned tables count their rows in each partition.
	rows, err := conn.Query(ctx, `select n.nspname, c.relname, c.reltuples from pg_class c
		join pg_namespace n on n.oid = c.relnamespace where c.relkind in ('r', 'm') and c.reltuples >= 0`)
	if err != nil {
		return nil, err
	}
	sizes := map[Table]float64{}
	var t Table
	var n float64
	_, err = pgx.ForEachRow(rows, []any{&t.Schema, &t.Name, &n}, func() error {
		sizes[t] = n
		return nil
	})
	return sizes, err
}
