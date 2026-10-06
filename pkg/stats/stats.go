// Package stats keeps per-statement numbers, as pg_stat_statements does, but by tenant and from the client's side of the proxy.
package stats

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json/v2"
	"fmt"
	"hash/maphash"
	"log/slog"
	"maps"
	"math"
	"os"
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
	At             time.Time // when it was answered; zero means when the table takes it in
	Database, Role string
	SQL            string        // the Query or Parse text
	Took           time.Duration // from when it went to Postgres to its answer; 0 when it shared a Sync with others, so has no time of its own
	Rows           int64         // from its CommandComplete
	Code           string        // the SQLSTATE of its error; "" when it succeeded
	Message        string        // the error's text, kept only with Table.ErrorText
	Rejected       bool          // QueryGuard refused it, not Postgres
	NotRun         bool          // it failed before running, at Parse or Bind
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
	Timed                               int64            // the calls that finished without an error and had a time of their own
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
	p99                time.Duration // cached for P99, from when timed was p99At
	p99At              int64
	p50v               time.Duration // cached for p50, from when timed was p50At
	p50At              int64
}

// Table gathers statements into rows; it is safe for concurrent use, and its zero value is ready.
type Table struct {
	Max       int                           // rows kept; the least called tenth goes to make room; 0 means DefaultMax
	ErrorText bool                          // keep each code's last error text, which can carry row values
	Tenant    func(role, sql string) string // the tenant a statement runs for; nil means its role
	// Traffic, when set, gets a record of each statement, for the policy simulator.
	Traffic *TrafficLog
	// Units gives the cost units a statement's time is worth on this server, for its traffic record; nil records none.
	Units func(time.Duration) (float64, bool)

	init    sync.Once
	queue   chan Statement
	dropped atomic.Int64

	mu           sync.Mutex
	rows         map[key]*row
	evicted      int64
	fingerprints map[uint64]string // statement text's hash to fingerprint, so a repeated text is parsed once without being kept
	seed         maphash.Seed
	buffers      map[owner]Buffers // from pg_stat_statements
	last         map[counterKey]Counters
	queryPrints  map[int64]string // pg_stat_statements query ID to fingerprint
	now          minute           // this minute's traffic, for anomalies
	baselines    map[string]*baseline
	incident     bool // an anomaly has started and not ended
	anomalies    []Anomaly
	flips        []Flip
}

// Flip is a plan flip lately seen.
type Flip struct {
	Database, Fingerprint, Query string
	At                           time.Time
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
	query = t.addToRow(k, query, st)
	if t.Traffic != nil {
		t.Traffic.write(t.record(st, k, query))
	}
}

// addToRow puts st in the row k, making it with query when new, and returns the row's text.
func (t *Table) addToRow(k key, query string, st Statement) string {
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
		return r.query
	case st.Code != "":
		r.errors = inc(r.errors, st.Code)
		if t.ErrorText {
			if r.lastErrors == nil {
				r.lastErrors = map[string]string{}
			}
			r.lastErrors[st.Code] = st.Message
		}
	}
	if st.NotRun {
		return r.query
	}
	// The minute is judged against the statement's usual runs, so it is counted before this one joins them.
	t.count(k, r, st)
	r.calls++
	r.n += st.Rows
	// A run cut short by an error, such as a timeout, says nothing of how long the statement takes.
	if st.Took > 0 && st.Code == "" {
		r.timed++
		r.total += st.Took
		r.took.add(st.Took)
	}
	return r.query
}

// fingerprint returns sql's fingerprint, and its text for a new row when that is known without parsing; the caller doesn't hold mu.
func (t *Table) fingerprint(sql string) (fingerprint, query string) {
	t.mu.Lock()
	if t.fingerprints == nil {
		t.fingerprints, t.seed = map[uint64]string{}, maphash.MakeSeed()
	}
	h := maphash.String(t.seed, sql)
	fp, ok := t.fingerprints[h]
	t.mu.Unlock()
	if !ok {
		fp = sqlparse.Fingerprint(sql)
		t.mu.Lock()
		// The cache only saves parsing, so it starts over once full rather than tracking use.
		if len(t.fingerprints) >= 4*t.max() {
			clear(t.fingerprints)
		}
		t.fingerprints[h] = fp
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
	// Finding the least called rows means going through them all, so a tenth go at once, not one for each new row.
	keys := slices.SortedFunc(maps.Keys(t.rows), func(a, b key) int { return cmp.Compare(t.rows[a].calls, t.rows[b].calls) })
	n := max(1, len(keys)/10)
	for _, k := range keys[:n] {
		delete(t.rows, k)
	}
	t.evicted += int64(n)
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
	// Parsing a reading's new texts can take a while, so it is done before taking mu, which admissions wait on; a map once stored isn't changed.
	t.mu.Lock()
	known := t.queryPrints
	t.mu.Unlock()
	prints := make(map[int64]string, len(cs))
	for _, c := range cs {
		fp, ok := known[c.QueryID]
		if !ok {
			fp = sqlparse.Fingerprint(c.Query)
		}
		prints[c.QueryID] = fp
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	last := make(map[counterKey]Counters, len(cs))
	seen := map[owner]bool{}
	if t.buffers == nil {
		t.buffers = map[owner]Buffers{}
	}
	for _, c := range cs {
		ck := counterKey{c.Database, c.Role, c.QueryID}
		fp := prints[c.QueryID]
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

// P99 returns the p99 of a row's timed calls and how many there were; 0 calls when there is no such row.
func (t *Table) P99(database, role, tenant, fingerprint string) (time.Duration, int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.rows[key{database, role, tenant, fingerprint}]
	if r == nil {
		return 0, 0
	}
	// Each admission may ask, so the quantile is worked out again only once the calls have grown by a sixteenth.
	if r.timed != r.p99At && (r.timed < 64 || r.timed-r.p99At >= r.timed/16) {
		r.p99, r.p99At = r.took.quantile(0.99), r.timed
	}
	return r.p99, r.timed
}

// WALPerCall returns the WAL a statement of role with fingerprint writes per call in database, by pg_stat_statements; false before it has counted one.
func (t *Table) WALPerCall(database, role, fingerprint string) (float64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.buffers[owner{database, role, fingerprint}]
	if b.Calls <= 0 {
		return 0, false
	}
	return b.WALBytes / float64(b.Calls), true
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

// How anomalies are found: each minute's p99, share of failed statements and share of slow ones are held against a moving baseline.
const (
	minuteCalls     = 20  // statements a minute needs before it says anything
	baselineMinutes = 30  // minutes the baseline is averaged over
	warmupMinutes   = 10  // minutes of baseline before anything is flagged
	raiseAfter      = 2   // anomalous minutes in a row that start an anomaly, so one spike raises nothing
	clearAfter      = 2   // normal minutes in a row that end one
	slowerThanUsual = 10  // a run this many times its statement's p50, and at least slowRun, is slow
	keptAnomalies   = 100 // anomalies Anomalies remembers
	namedStatements = 3   // statements an anomaly names
)

// slowRun is the shortest run counted as slow: under load a quick statement now and then takes tens of milliseconds.
const slowRun = 100 * time.Millisecond

// signals are what each minute is judged on, with the least a minute's value must reach to be anomalous whatever the baseline.
var signals = []struct {
	name  string
	floor float64
}{
	{"p99", 0.05}, // seconds
	{"errors", 0.02},
	{"slow", 0.05},
}

// Anomaly is one incident: signals that stayed well above their baselines, until all are back; or its end.
type Anomaly struct {
	Signals    []Reading // those that started it, or those whose return ended it
	At         time.Time // the end of the minute that started or ended it
	Ended      bool
	Statements []string // the statements behind it, most first
	Flips      []string // statements whose plan flipped that minute
	LockWaits  int      // the most sessions waiting on locks at once that minute
}

// Reading is one signal's value in a minute, against its baseline.
type Reading struct {
	Signal          string // p99 (seconds), errors (the share of statements that failed) or slow (the share far slower than their usual)
	Value, Baseline float64
}

func (r Reading) String() string {
	return fmt.Sprintf("%s=%g (baseline %g)", r.Signal, r.Value, r.Baseline)
}

// minute is one minute's traffic.
type minute struct {
	calls, errors, slow int64
	took                sketch
	byKey               map[key]*minuteRow
	flips               map[owner]bool
	lockWaits           int
}

type minuteRow struct {
	calls, errors, slow int64
	took                time.Duration
}

// baseline is a signal's moving mean and mean absolute deviation, and where its anomaly stands.
type baseline struct {
	mean, dev    float64
	n            int
	above, below int // anomalous and normal minutes in a row
	active       bool
}

// count adds st to the minute; the caller holds mu, and r is st's row.
func (t *Table) count(k key, r *row, st Statement) {
	if t.now.byKey == nil {
		t.now.byKey = map[key]*minuteRow{}
	}
	m := t.now.byKey[k]
	if m == nil {
		m = &minuteRow{}
		t.now.byKey[k] = m
	}
	t.now.calls++
	m.calls++
	if st.Code != "" {
		t.now.errors++
		m.errors++
	}
	if st.Took > 0 {
		t.now.took.add(st.Took)
		m.took += st.Took
		if r.timed >= minuteCalls && st.Took >= slowRun && st.Took > slowerThanUsual*r.p50() {
			t.now.slow++
			m.slow++
		}
	}
}

// Flipped notes that a statement's plan flipped this minute.
func (t *Table) Flipped(database, fingerprint string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.now.flips == nil {
		t.now.flips = map[owner]bool{}
	}
	t.now.flips[owner{database: database, fingerprint: fingerprint}] = true
	t.flips = append(t.flips, Flip{Database: database, Fingerprint: fingerprint, At: time.Now()})
	if extra := len(t.flips) - keptAnomalies; extra > 0 {
		t.flips = slices.Delete(t.flips, 0, extra)
	}
}

// Flips returns the plan flips lately seen, oldest first, with the text of a statement of each.
func (t *Table) Flips() []Flip {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := slices.Clone(t.flips)
	for i, f := range out {
		for k, r := range t.rows {
			if k.database == f.Database && k.fingerprint == f.Fingerprint {
				out[i].Query = r.query
				break
			}
		}
	}
	return out
}

// LockWaits notes how many sessions wait on locks now; the minute keeps the most.
func (t *Table) LockWaits(n int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.now.lockWaits = max(t.now.lockWaits, n)
}

// Minute ends the minute at now and returns the anomalies it started or ended.
func (t *Table) Minute(now time.Time) []Anomaly {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := t.now
	t.now = minute{}
	// Too few calls say nothing either way, and a server too slow to finish many mustn't look calm, so anomalies neither start nor end.
	if m.calls < minuteCalls {
		return nil
	}
	values := map[string]float64{
		"p99":    m.took.quantile(0.99).Seconds(),
		"errors": float64(m.errors) / float64(m.calls),
		"slow":   float64(m.slow) / float64(m.calls),
	}
	var raised, cleared []Reading
	for _, sig := range signals {
		b := t.baselines[sig.name]
		if b == nil {
			b = &baseline{}
			if t.baselines == nil {
				t.baselines = map[string]*baseline{}
			}
			t.baselines[sig.name] = b
		}
		v := values[sig.name]
		anomalous := b.n >= warmupMinutes && v > sig.floor && v > 2*b.mean && v > b.mean+3*b.dev
		if anomalous {
			b.above, b.below = b.above+1, 0
		} else {
			b.above, b.below = 0, b.below+1
			// An anomalous minute stays out of the baseline, so a long incident isn't learned as normal.
			w := float64(min(b.n+1, baselineMinutes))
			b.mean += (v - b.mean) / w
			b.dev += (math.Abs(v-b.mean) - b.dev) / w
			b.n++
		}
		switch r := (Reading{Signal: sig.name, Value: v, Baseline: b.mean}); {
		case !b.active && b.above >= raiseAfter:
			b.active = true
			raised = append(raised, r)
		case b.active && b.below >= clearAfter:
			b.active = false
			cleared = append(cleared, r)
		}
	}
	// A signal rising during an incident is part of it, so an incident starts and ends one anomaly.
	var out []Anomaly
	active := slices.ContainsFunc(slices.Collect(maps.Values(t.baselines)), func(b *baseline) bool { return b.active })
	switch {
	case !t.incident && len(raised) > 0:
		t.incident = true
		out = append(out, t.anomaly(raised, now, false, m))
	case t.incident && !active:
		t.incident = false
		out = append(out, t.anomaly(cleared, now, true, m))
	}
	t.anomalies = append(t.anomalies, out...)
	if extra := len(t.anomalies) - keptAnomalies; extra > 0 {
		t.anomalies = slices.Delete(t.anomalies, 0, extra)
	}
	return out
}

// anomaly describes readings in minute m, naming the statements behind them; the caller holds mu.
func (t *Table) anomaly(readings []Reading, at time.Time, ended bool, m minute) Anomaly {
	a := Anomaly{Signals: readings, At: at, Ended: ended, LockWaits: m.lockWaits}
	if ended {
		return a
	}
	keys := slices.Collect(maps.Keys(m.byKey))
	errs := slices.ContainsFunc(readings, func(r Reading) bool { return r.Signal == "errors" })
	slow := slices.ContainsFunc(readings, func(r Reading) bool { return r.Signal != "errors" })
	weight := func(k key) (n int64, took time.Duration) {
		r := m.byKey[k]
		if errs {
			n += r.errors
		}
		if slow {
			n, took = n+r.slow, r.took
		}
		return n, took
	}
	slices.SortFunc(keys, func(x, y key) int {
		xn, xt := weight(x)
		yn, yt := weight(y)
		return cmp.Or(cmp.Compare(yn, xn), cmp.Compare(yt, xt), cmp.Compare(x.fingerprint, y.fingerprint))
	})
	// Once some statements failed or ran slow, the rest only shared the minute with them.
	var most int64
	if len(keys) > 0 {
		most, _ = weight(keys[0])
	}
	for _, k := range keys {
		if n, took := weight(k); (n == 0 && (most > 0 || took == 0)) || len(a.Statements) == namedStatements {
			break
		}
		if r := t.rows[k]; r != nil && !slices.Contains(a.Statements, r.query) {
			a.Statements = append(a.Statements, r.query)
		}
	}
	for o := range m.flips {
		for k, r := range t.rows {
			if k.database == o.database && k.fingerprint == o.fingerprint {
				a.Flips = append(a.Flips, r.query)
				break
			}
		}
	}
	slices.Sort(a.Flips)
	return a
}

// Anomalies returns the anomalies started and ended lately, oldest first.
func (t *Table) Anomalies() []Anomaly {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.anomalies)
}

// p50 returns the row's median run, worked out again only once its runs have grown by a sixteenth.
func (r *row) p50() time.Duration {
	if r.timed != r.p50At && (r.timed < 64 || r.timed-r.p50At >= r.timed/16) {
		r.p50v, r.p50At = r.took.quantile(0.5), r.timed
	}
	return r.p50v
}

// Record is one statement in the traffic log: what the policy simulator replays.
type Record struct {
	At          time.Time `json:"at"`
	Database    string    `json:"database"`
	Role        string    `json:"role"`
	Tenant      string    `json:"tenant"`
	Fingerprint string    `json:"fingerprint"`
	Query       string    `json:"query"` // with its constants as $1, $2…, so the log holds no values
	TookMS      float64   `json:"took_ms,omitzero"`
	Units       float64   `json:"units,omitzero"` // the cost units its time was worth on the server
	Rows        int64     `json:"rows,omitzero"`
	Code        string    `json:"code,omitempty"`
	Rejected    bool      `json:"rejected,omitzero"`
	NotRun      bool      `json:"not_run,omitzero"`
}

// record makes st's traffic record.
func (t *Table) record(st Statement, k key, query string) Record {
	rec := Record{At: cmp.Or(st.At, time.Now()), Database: k.database, Role: k.role, Tenant: k.tenant, Fingerprint: k.fingerprint,
		Query: query, TookMS: float64(st.Took) / float64(time.Millisecond), Rows: st.Rows, Code: st.Code, Rejected: st.Rejected, NotRun: st.NotRun}
	if t.Units != nil && st.Took > 0 {
		rec.Units, _ = t.Units(st.Took)
	}
	return rec
}

// trafficKept is how long one traffic file is written before it moves aside, so the log holds between one and two days.
const trafficKept = 24 * time.Hour

// TrafficLog writes traffic records as JSON lines to Path, moving the file to Path.1 once it holds a day.
type TrafficLog struct {
	Path string
	Log  *slog.Logger // where write errors go; nil means slog.Default()

	now     func() time.Time // nil means time.Now
	mu      sync.Mutex
	f       *os.File
	started time.Time // the time of the file's first record
	failed  bool      // a write failed, which was logged; the next success clears it
}

func (l *TrafficLog) write(rec Record) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.writeLocked(rec); err != nil {
		if !l.failed {
			cmp.Or(l.Log, slog.Default()).Error("write traffic log", "file", l.Path, "err", err)
		}
		l.failed = true
		return
	}
	l.failed = false
}

func (l *TrafficLog) writeLocked(rec Record) error {
	now := time.Now
	if l.now != nil {
		now = l.now
	}
	if l.f == nil {
		if err := l.open(); err != nil {
			return err
		}
	}
	if !l.started.IsZero() && now().Sub(l.started) >= trafficKept {
		l.f.Close()
		l.f = nil
		if err := os.Rename(l.Path, l.Path+".1"); err != nil {
			return err
		}
		if err := l.open(); err != nil {
			return err
		}
	}
	if l.started.IsZero() {
		l.started = rec.At
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = l.f.Write(append(line, '\n'))
	return err
}

// open opens Path to append, learning when its first record was written.
func (l *TrafficLog) open() error {
	f, err := os.OpenFile(l.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	l.f, l.started = f, time.Time{}
	if recs, _, err := readTraffic(l.Path, 1); err == nil && len(recs) > 0 {
		l.started = recs[0].At
	}
	return nil
}

// Close closes the file.
func (l *TrafficLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// ReadTraffic reads every record in a traffic log file, and counts the lines it skipped for not being one.
func ReadTraffic(path string) (records []Record, skipped int, err error) {
	return readTraffic(path, -1)
}

// readTraffic reads up to n records of path, skipping lines that aren't one, as a crash mid-write leaves; n below 0 reads them all.
func readTraffic(path string, n int) (records []Record, skipped int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	lines := bufio.NewScanner(f)
	lines.Buffer(make([]byte, 64<<10), 16<<20)
	for lines.Scan() && n != 0 {
		var rec Record
		if json.Unmarshal(lines.Bytes(), &rec) != nil {
			skipped++
			continue
		}
		records = append(records, rec)
		n--
	}
	if err := lines.Err(); err != nil {
		return records, skipped, fmt.Errorf("%s: %w", path, err)
	}
	return records, skipped, nil
}
