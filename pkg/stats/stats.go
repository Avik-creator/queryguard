// Package stats keeps per-statement numbers, as pg_stat_statements does, but by tenant and from the client's side of the proxy.
package stats

import (
	"cmp"
	"context"
	"maps"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Avik-creator/queryguard/pkg/sqlparse"
)

// DefaultMax is how many rows a Table keeps when Max is 0, as pg_stat_statements.max does.
const DefaultMax = 5000

// queueSize is how many statements Record holds for Run; past it they are dropped, so a session never waits on stats.
const queueSize = 4096

// unparsable stands for the text of statements Postgres's parser rejects, whose own text may hold values.
const unparsable = "(unparsable)"

// Statement is one finished statement as a session saw it.
type Statement struct {
	Database, Role string
	SQL            string        // the Query or Parse text
	Took           time.Duration // from when it went to Postgres to its answer; 0 when it shared a Sync with others, so has no time of its own
	Rows           int64         // from its CommandComplete
	Code           string        // the SQLSTATE of its error; "" when it succeeded
	Message        string        // the error's text, kept only with Table.ErrorText
	Rejected       bool          // QueryGuard refused it, not Postgres
}

// Counters are one pg_stat_statements entry's cumulative numbers.
type Counters struct {
	Database, Role, Query string
	QueryID               int64
	Calls                 int64
	SharedHit, SharedRead int64 // shared buffer hits and reads
	TempRead, TempWritten int64 // temporary file blocks, as when a sort or hash spills past work_mem
	WALBytes              float64
}

// Buffers are what pg_stat_statements counted for a row's database, role and fingerprint since it was last reset.
type Buffers struct {
	Calls                 int64
	SharedHit, SharedRead int64
	TempRead, TempWritten int64
	WALBytes              float64
}

// Row is the numbers of one statement fingerprint run by one tenant through one role in one database.
type Row struct {
	Database, Role, Tenant, Fingerprint string
	Query                               string           // the first text seen, with its constants as $1, $2…
	Calls                               int64            // statements Postgres ran, failed or not
	Timed                               int64            // the calls that had a time of their own
	Rows                                int64            // returned or changed
	Total                               time.Duration    // over the timed calls
	P50, P95, P99                       time.Duration    // of the timed calls
	Errors                              map[string]int64 // Postgres's errors, by SQLSTATE
	Rejections                          map[string]int64 // QueryGuard's own refusals, by SQLSTATE
	LastErrors                          map[string]string
	Buffers                             Buffers
}

// key names a row.
type key struct{ database, role, tenant, fingerprint string }

// owner names what pg_stat_statements counts apart: it knows roles, not tenants.
type owner struct{ database, role, fingerprint string }

// row is a Row as it is being filled.
type row struct {
	query              string
	calls, timed, n    int64
	total              time.Duration
	took               sketch
	errors, rejections map[string]int64
	lastErrors         map[string]string
}

// Table gathers statements into rows; it is safe for concurrent use, and its zero value is ready.
type Table struct {
	Max       int                           // rows kept; the least called row goes to make room; 0 means DefaultMax
	ErrorText bool                          // keep each code's last error text, which can carry row values
	Tenant    func(role, sql string) string // the tenant a statement runs for; nil means its role

	init    sync.Once
	queue   chan Statement
	dropped atomic.Int64

	mu           sync.Mutex
	rows         map[key]*row
	evicted      int64
	fingerprints map[string]string // statement text to fingerprint, so a repeated text is parsed once
	buffers      map[owner]Buffers // from pg_stat_statements
	last         map[counterKey]Counters
	queryPrints  map[int64]string // pg_stat_statements query ID to fingerprint
}

// counterKey names a pg_stat_statements entry.
type counterKey struct {
	database, role string
	id             int64
}

func (t *Table) start() { t.init.Do(func() { t.queue = make(chan Statement, queueSize) }) }

// Record queues st for Run without waiting; when the queue is full st is dropped and counted.
func (t *Table) Record(st Statement) {
	t.start()
	select {
	case t.queue <- st:
	default:
		t.dropped.Add(1)
	}
}

// Run adds recorded statements to their rows until ctx ends; parsing happens here, off the sessions' path.
func (t *Table) Run(ctx context.Context) {
	t.start()
	for {
		select {
		case <-ctx.Done():
			return
		case st := <-t.queue:
			t.add(st)
		}
	}
}

// Dropped returns how many statements Record dropped because Run fell behind.
func (t *Table) Dropped() int64 { return t.dropped.Load() }

// Evicted returns how many rows went to make room for new ones.
func (t *Table) Evicted() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.evicted
}

// add puts st in its row.
func (t *Table) add(st Statement) {
	fingerprint, query := t.fingerprint(st.SQL)
	tenant := st.Role
	if t.Tenant != nil {
		tenant = t.Tenant(st.Role, st.SQL)
	}
	k := key{st.Database, st.Role, tenant, fingerprint}

	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.rows[k]
	if r == nil {
		t.makeRoom()
		if query == "" {
			query = sqlparse.Normalize(st.SQL)
		}
		r = &row{query: query}
		if t.rows == nil {
			t.rows = map[key]*row{}
		}
		t.rows[k] = r
	}
	switch {
	case st.Rejected:
		r.rejections = inc(r.rejections, st.Code)
		return
	case st.Code != "":
		r.errors = inc(r.errors, st.Code)
		if t.ErrorText {
			if r.lastErrors == nil {
				r.lastErrors = map[string]string{}
			}
			r.lastErrors[st.Code] = st.Message
		}
	}
	r.calls++
	r.n += st.Rows
	if st.Took > 0 {
		r.timed++
		r.total += st.Took
		r.took.add(st.Took)
	}
}

// fingerprint returns sql's fingerprint, and its text for a new row when that is known without parsing; the caller doesn't hold mu.
func (t *Table) fingerprint(sql string) (fingerprint, query string) {
	t.mu.Lock()
	fp, ok := t.fingerprints[sql]
	t.mu.Unlock()
	if !ok {
		fp = sqlparse.Fingerprint(sql)
		t.mu.Lock()
		// The cache only saves parsing, so it starts over once full rather than tracking use.
		if t.fingerprints == nil || len(t.fingerprints) >= 4*t.max() {
			t.fingerprints = map[string]string{}
		}
		t.fingerprints[sql] = fp
		t.mu.Unlock()
	}
	if fp == "" {
		return unparsable, unparsable
	}
	return fp, ""
}

func (t *Table) max() int { return cmp.Or(t.Max, DefaultMax) }

// makeRoom drops the least called row when the table is full, as pg_stat_statements deallocates; the caller holds mu.
func (t *Table) makeRoom() {
	if len(t.rows) < t.max() {
		return
	}
	var least key
	var fewest *row
	for k, r := range t.rows {
		if fewest == nil || r.calls < fewest.calls {
			least, fewest = k, r
		}
	}
	delete(t.rows, least)
	t.evicted++
}

func inc(m map[string]int64, code string) map[string]int64 {
	if m == nil {
		m = map[string]int64{}
	}
	m[code]++
	return m
}

// Counters takes a reading of pg_stat_statements; each entry's growth since the last reading is added to its row's Buffers.
func (t *Table) Counters(cs []Counters) {
	t.mu.Lock()
	defer t.mu.Unlock()
	last := make(map[counterKey]Counters, len(cs))
	prints := make(map[int64]string, len(cs))
	seen := map[owner]bool{}
	if t.buffers == nil {
		t.buffers = map[owner]Buffers{}
	}
	for _, c := range cs {
		ck := counterKey{c.Database, c.Role, c.QueryID}
		fp, ok := t.queryPrints[c.QueryID]
		if !ok {
			fp = sqlparse.Fingerprint(c.Query)
		}
		prints[c.QueryID] = fp
		before := t.last[ck]
		// Counters that fell were reset, or the entry was dropped and made again, so all of them are new.
		if c.Calls < before.Calls {
			before = Counters{}
		}
		last[ck] = c
		o := owner{c.Database, c.Role, cmp.Or(fp, unparsable)}
		seen[o] = true
		b := t.buffers[o]
		b.Calls += c.Calls - before.Calls
		b.SharedHit += c.SharedHit - before.SharedHit
		b.SharedRead += c.SharedRead - before.SharedRead
		b.TempRead += c.TempRead - before.TempRead
		b.TempWritten += c.TempWritten - before.TempWritten
		b.WALBytes += c.WALBytes - before.WALBytes
		t.buffers[o] = b
	}
	t.last, t.queryPrints = last, prints
	// What pg_stat_statements no longer has and no row shows goes, so the map stays as small as theirs.
	shown := map[owner]bool{}
	for k := range t.rows {
		shown[owner{k.database, k.role, k.fingerprint}] = true
	}
	for o := range t.buffers {
		if !seen[o] && !shown[o] {
			delete(t.buffers, o)
		}
	}
}

// Rows returns every row, most total time first.
func (t *Table) Rows() []Row {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Row, 0, len(t.rows))
	for k, r := range t.rows {
		out = append(out, Row{
			Database: k.database, Role: k.role, Tenant: k.tenant, Fingerprint: k.fingerprint, Query: r.query,
			Calls: r.calls, Timed: r.timed, Rows: r.n, Total: r.total,
			P50: r.took.quantile(0.5), P95: r.took.quantile(0.95), P99: r.took.quantile(0.99),
			Errors: maps.Clone(r.errors), Rejections: maps.Clone(r.rejections), LastErrors: maps.Clone(r.lastErrors),
			Buffers: t.buffers[owner{k.database, k.role, k.fingerprint}],
		})
	}
	slices.SortFunc(out, func(a, b Row) int {
		return cmp.Or(cmp.Compare(b.Total, a.Total), cmp.Compare(b.Calls, a.Calls), cmp.Compare(a.Fingerprint, b.Fingerprint),
			cmp.Compare(a.Tenant, b.Tenant))
	})
	return out
}

// gamma is the ratio between a sketch's bucket bounds; a quantile is off by at most (gamma-1)/2, under 1%.
const gamma = 1.02

var logGamma = math.Log(gamma)

// sketch counts durations in buckets that grow by gamma, as DDSketch does, so quantiles keep a relative error at any scale.
type sketch struct {
	counts map[int]int64
	n      int64
}

func (s *sketch) add(d time.Duration) {
	if d <= 0 {
		return
	}
	if s.counts == nil {
		s.counts = map[int]int64{}
	}
	s.counts[int(math.Ceil(math.Log(float64(d))/logGamma))]++
	s.n++
}

// quantile returns the duration q of the way up, the middle of its bucket; 0 when the sketch is empty.
func (s *sketch) quantile(q float64) time.Duration {
	if s.n == 0 {
		return 0
	}
	rank := int64(math.Ceil(q * float64(s.n)))
	var seen int64
	for _, i := range slices.Sorted(maps.Keys(s.counts)) {
		if seen += s.counts[i]; seen >= max(rank, 1) {
			return time.Duration(2 * math.Pow(gamma, float64(i)) / (gamma + 1))
		}
	}
	return 0
}
