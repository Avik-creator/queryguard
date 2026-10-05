package stats

import (
	"math"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
	"unsafe"

	"github.com/Avik-creator/queryguard/pkg/sqlparse"
)

func TestSketchQuantilesAreWithinOnePercent(t *testing.T) {
	var s sketch
	for i := range 1000 {
		s.add(time.Duration(i+1) * time.Millisecond)
	}

	for q, want := range map[float64]time.Duration{0.5: 500 * time.Millisecond, 0.95: 950 * time.Millisecond, 0.99: 990 * time.Millisecond} {
		got := s.quantile(q)
		if diff := math.Abs(float64(got-want)) / float64(want); diff > 0.01 {
			t.Errorf("quantile(%v) = %v; want %v within 1%%", q, got, want)
		}
	}
}

func TestSketchWithNothingIsZero(t *testing.T) {
	var s sketch
	if got := s.quantile(0.99); got != 0 {
		t.Errorf("quantile of nothing = %v; want 0", got)
	}
}

func TestRowsGroupStatementsByFingerprintAndTenant(t *testing.T) {
	var tb Table
	tb.add(Statement{Database: "shop", Role: "app", SQL: "select * from orders where id = 1", Took: 10 * time.Millisecond, Rows: 1})
	tb.add(Statement{Database: "shop", Role: "app", SQL: "SELECT * FROM orders WHERE id = 2", Took: 30 * time.Millisecond, Rows: 1})
	tb.add(Statement{Database: "shop", Role: "other", SQL: "select * from orders where id = 3", Took: time.Millisecond})

	rows := tb.Rows()
	if len(rows) != 2 {
		t.Fatalf("got %d rows; want one per role: %+v", len(rows), rows)
	}
	r := find(t, rows, "app")
	if r.Calls != 2 || r.Rows != 2 || r.Total != 40*time.Millisecond || r.Query != "select * from orders where id = $1" {
		t.Errorf("row %+v; want 2 calls, 2 rows, 40ms and the normalized text", r)
	}
	if r.P99 < 29*time.Millisecond || r.P99 > 31*time.Millisecond {
		t.Errorf("p99 = %v; want about 30ms", r.P99)
	}
}

func TestStatementsWithoutTheirOwnTimeAreCountedNotTimed(t *testing.T) {
	var tb Table
	tb.add(Statement{Database: "shop", Role: "app", SQL: "select 1", Took: 5 * time.Millisecond})
	tb.add(Statement{Database: "shop", Role: "app", SQL: "select 2"})

	r := tb.Rows()[0]
	if r.Calls != 2 || r.Timed != 1 || r.P50 != r.P99 {
		t.Errorf("row %+v; want 2 calls, 1 timed", r)
	}
}

func TestErrorsAndRejectionsAreKeptApartByCode(t *testing.T) {
	var tb Table
	tb.add(Statement{Database: "shop", Role: "app", SQL: "select 1/0", Code: "22012", Message: "division by zero"})
	tb.add(Statement{Database: "shop", Role: "app", SQL: "select 1/0", Code: "22012", Message: "division by zero"})
	tb.add(Statement{Database: "shop", Role: "app", SQL: "select 1/0", Code: "54000", Rejected: true})

	r := tb.Rows()[0]
	if r.Errors["22012"] != 2 || r.Rejections["54000"] != 1 || len(r.Errors) != 1 {
		t.Errorf("errors %v, rejections %v; want 2 division errors and 1 rejection apart", r.Errors, r.Rejections)
	}
	if r.Calls != 2 {
		t.Errorf("calls = %d; want only the 2 statements Postgres ran", r.Calls)
	}
	if len(r.LastErrors) != 0 {
		t.Errorf("kept error text %v; want none unless ErrorText is set", r.LastErrors)
	}
}

func TestErrorTextIsKeptWhenAskedFor(t *testing.T) {
	tb := Table{ErrorText: true}
	tb.add(Statement{Database: "shop", Role: "app", SQL: "select 1/0", Code: "22012", Message: "division by zero"})

	if got := tb.Rows()[0].LastErrors["22012"]; got != "division by zero" {
		t.Errorf("last error = %q; want the message", got)
	}
}

func TestTenantComesFromTheTenantFunc(t *testing.T) {
	tb := Table{Tenant: func(role, sql string) string { return role + "/acme" }}
	tb.add(Statement{Database: "shop", Role: "app", SQL: "select 1 /*tenant='acme'*/"})

	if r := tb.Rows()[0]; r.Tenant != "app/acme" || r.Role != "app" {
		t.Errorf("row %+v; want tenant app/acme for role app", r)
	}
}

func TestUnparsableStatementsShareOneRowWithoutTheirText(t *testing.T) {
	var tb Table
	tb.add(Statement{Database: "shop", Role: "app", SQL: "selec 'secret'", Code: "42601"})
	tb.add(Statement{Database: "shop", Role: "app", SQL: "updat 'other secret'", Code: "42601"})

	rows := tb.Rows()
	if len(rows) != 1 || rows[0].Query != unparsable || rows[0].Errors["42601"] != 2 {
		t.Errorf("rows %+v; want one row of 2 syntax errors with no text", rows)
	}
}

func TestLeastCalledRowGoesWhenFull(t *testing.T) {
	tb := Table{Max: 2}
	for range 3 {
		tb.add(Statement{Database: "shop", Role: "app", SQL: "select a from t"})
	}
	tb.add(Statement{Database: "shop", Role: "app", SQL: "select b from t"})
	tb.add(Statement{Database: "shop", Role: "app", SQL: "select c from t"})

	rows := tb.Rows()
	if len(rows) != 2 {
		t.Fatalf("got %d rows; want 2", len(rows))
	}
	for _, r := range rows {
		if r.Query == "select b from t" {
			t.Errorf("rows %+v; want the least called, b, gone", rows)
		}
	}
	if tb.Evicted() != 1 {
		t.Errorf("evicted %d; want 1", tb.Evicted())
	}
}

func TestRecordIsTakenUpByRun(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var tb Table
		go tb.Run(t.Context())

		tb.Record(Statement{Database: "shop", Role: "app", SQL: "select 1", Took: time.Millisecond})
		synctest.Wait()

		if rows := tb.Rows(); len(rows) != 1 || rows[0].Calls != 1 {
			t.Errorf("rows %+v; want the recorded statement", rows)
		}
	})
}

func TestRecordDropsWhatItCannotQueue(t *testing.T) {
	var tb Table
	for range queueSize + 5 {
		tb.Record(Statement{Database: "shop", Role: "app", SQL: "select 1"})
	}

	if tb.Dropped() != 5 {
		t.Errorf("dropped %d; want the 5 past the queue", tb.Dropped())
	}
}

func TestCountersAddTheirGrowthToTheStatementsRole(t *testing.T) {
	var tb Table
	tb.add(Statement{Database: "shop", Role: "app", SQL: "select * from orders where id = 1"})
	pgss := Counters{Database: "shop", Role: "app", QueryID: 7, Query: "select * from orders where id = $1", Calls: 10, SharedHit: 100,
		SharedRead: 5, TempWritten: 2, WALBytes: 0}
	tb.Counters([]Counters{pgss})
	pgss.Calls, pgss.SharedHit, pgss.SharedRead = 12, 130, 6
	tb.Counters([]Counters{pgss})

	b := tb.Rows()[0].Buffers
	if b.Calls != 12 || b.SharedHit != 130 || b.SharedRead != 6 || b.TempWritten != 2 {
		t.Errorf("buffers %+v; want the counters as they grew", b)
	}
}

func TestCountersThatFallStartAgainFromZero(t *testing.T) {
	var tb Table
	tb.add(Statement{Database: "shop", Role: "app", SQL: "select 1"})
	pgss := Counters{Database: "shop", Role: "app", QueryID: 7, Query: "select $1", Calls: 10, SharedHit: 100}
	tb.Counters([]Counters{pgss})
	// pg_stat_statements_reset, or the entry deallocated and made again.
	pgss.Calls, pgss.SharedHit = 1, 4
	tb.Counters([]Counters{pgss})

	if b := tb.Rows()[0].Buffers; b.Calls != 11 || b.SharedHit != 104 {
		t.Errorf("buffers %+v; want 11 calls and 104 hits", b)
	}
}

func find(t *testing.T, rows []Row, role string) Row {
	t.Helper()
	for _, r := range rows {
		if r.Role == role {
			return r
		}
	}
	t.Fatalf("no row for role %s in %+v", role, rows)
	return Row{}
}

func TestErrorsBeforeRunningAreNotCalls(t *testing.T) {
	var tb Table
	tb.add(Statement{Database: "shop", Role: "app", SQL: "select $1::int", Code: "22P02", NotRun: true})

	if r := tb.Rows()[0]; r.Calls != 0 || r.Errors["22P02"] != 1 {
		t.Errorf("row %+v; want the Bind's error counted and no call", r)
	}
}

func TestWALPerCallIsTheAverageOfTheRolesStatement(t *testing.T) {
	var tb Table
	if _, ok := tb.WALPerCall("shop", "app", sqlparse.Fingerprint("update t set x = 1")); ok {
		t.Error("WALPerCall known before any reading")
	}
	tb.Counters([]Counters{{Database: "shop", Role: "app", QueryID: 3, Query: "update t set x = $1", Calls: 4, WALBytes: 4000}})

	if w, ok := tb.WALPerCall("shop", "app", sqlparse.Fingerprint("update t set x = 2")); !ok || w != 1000 {
		t.Errorf("WALPerCall = %v, %v; want 1000", w, ok)
	}
}

func TestP99OfARowFollowsItsTimedCalls(t *testing.T) {
	var tb Table
	fp := sqlparse.Fingerprint("select * from orders where id = 1")
	if _, n := tb.P99("shop", "app", "app", fp); n != 0 {
		t.Errorf("P99 of an unknown row counted %d calls; want 0", n)
	}
	for i := range 200 {
		tb.add(Statement{Database: "shop", Role: "app", SQL: "select * from orders where id = 1", Took: time.Duration(i+1) * time.Millisecond})
	}

	d, n := tb.P99("shop", "app", "app", fp)
	if n != 200 || d < 195*time.Millisecond || d > 201*time.Millisecond {
		t.Errorf("P99 = %v over %d calls; want about 198ms over 200", d, n)
	}
}

// minuteOf adds n statements to tb as one minute's traffic: fast ones, then slow ones of slowSQL, and errors of errSQL.
func minuteOf(tb *Table, fast, slow, errs int, took time.Duration) {
	for range fast {
		tb.add(Statement{Database: "shop", Role: "app", SQL: "select * from orders where id = 1", Took: 5 * time.Millisecond})
	}
	for range slow {
		tb.add(Statement{Database: "shop", Role: "app", SQL: "select * from orders where note like 'x'", Took: took})
	}
	for range errs {
		tb.add(Statement{Database: "shop", Role: "app", SQL: "insert into orders values (1)", Code: "23505"})
	}
}

func TestAnomalyNeedsTwoMinutesAboveTheBaselineAndEndsAfterTwoBelow(t *testing.T) {
	var tb Table
	now := time.Now()
	for i := range 15 {
		minuteOf(&tb, 100, 2, 0, 10*time.Millisecond)
		if got := tb.Minute(now.Add(time.Duration(i) * time.Minute)); len(got) != 0 {
			t.Fatalf("steady minute %d raised %+v", i, got)
		}
	}

	// One spike raises nothing.
	minuteOf(&tb, 100, 20, 0, 2*time.Second)
	if got := tb.Minute(now.Add(15 * time.Minute)); len(got) != 0 {
		t.Fatalf("one slow minute raised %+v; want nothing until a second", got)
	}
	minuteOf(&tb, 100, 2, 0, 10*time.Millisecond)
	tb.Minute(now.Add(16 * time.Minute))

	minuteOf(&tb, 100, 20, 0, 2*time.Second)
	tb.Minute(now.Add(17 * time.Minute))
	tb.Flipped("shop", sqlparse.Fingerprint("select * from orders where note like 'x'"))
	tb.LockWaits(7)
	minuteOf(&tb, 100, 20, 0, 2*time.Second)
	got := tb.Minute(now.Add(18 * time.Minute))
	var p99 *Anomaly
	for i := range got {
		if got[i].Signal == "p99" {
			p99 = &got[i]
		}
	}
	if p99 == nil || p99.Ended {
		t.Fatalf("two slow minutes raised %+v; want a p99 anomaly", got)
	}
	if len(p99.Statements) == 0 || p99.Statements[0] != "select * from orders where note like $1" {
		t.Errorf("anomaly names %q; want the slow statement first", p99.Statements)
	}
	if len(p99.Flips) != 1 || p99.LockWaits != 7 {
		t.Errorf("anomaly flips %q, lock waits %d; want the flipped statement and 7", p99.Flips, p99.LockWaits)
	}

	minuteOf(&tb, 100, 2, 0, 10*time.Millisecond)
	if got := tb.Minute(now.Add(19 * time.Minute)); len(got) != 0 {
		t.Fatalf("first normal minute gave %+v; want the anomaly to last", got)
	}
	minuteOf(&tb, 100, 2, 0, 10*time.Millisecond)
	ended := tb.Minute(now.Add(20 * time.Minute))
	if !slices.ContainsFunc(ended, func(a Anomaly) bool { return a.Signal == "p99" && a.Ended }) {
		t.Errorf("two normal minutes gave %+v; want the p99 anomaly ended", ended)
	}
	if a := tb.Anomalies(); !slices.ContainsFunc(a, func(a Anomaly) bool { return a.Signal == "p99" }) {
		t.Errorf("Anomalies = %+v; want the p99 one remembered", a)
	}
}

func TestErrorRateAnomalyNamesTheFailingStatement(t *testing.T) {
	var tb Table
	now := time.Now()
	for i := range 15 {
		minuteOf(&tb, 100, 0, 0, 0)
		tb.Minute(now.Add(time.Duration(i) * time.Minute))
	}
	var got []Anomaly
	for i := range 2 {
		minuteOf(&tb, 100, 0, 30, 0)
		got = tb.Minute(now.Add(time.Duration(15+i) * time.Minute))
	}

	if len(got) != 1 || got[0].Signal != "errors" || got[0].Statements[0] != "insert into orders values ($1)" {
		t.Errorf("got %+v; want an errors anomaly naming the insert", got)
	}
}

func TestQuietMinutesRaiseNothing(t *testing.T) {
	var tb Table
	now := time.Now()
	for i := range 15 {
		minuteOf(&tb, 100, 0, 0, 0)
		tb.Minute(now.Add(time.Duration(i) * time.Minute))
	}
	// A handful of statements, all failing, is too few to say anything.
	for i := range 3 {
		minuteOf(&tb, 2, 0, 3, 0)
		if got := tb.Minute(now.Add(time.Duration(15+i) * time.Minute)); len(got) != 0 {
			t.Fatalf("quiet minute raised %+v", got)
		}
	}
}

func TestFlipsListsRecentFlipsWithTheirText(t *testing.T) {
	var tb Table
	tb.add(Statement{Database: "shop", Role: "app", SQL: "select * from orders where id = 1"})
	tb.Flipped("shop", sqlparse.Fingerprint("select * from orders where id = 2"))

	if f := tb.Flips(); len(f) != 1 || f[0].Query != "select * from orders where id = $1" || f[0].At.IsZero() {
		t.Errorf("Flips = %+v; want the flip with its statement's text", f)
	}
}

func TestTrafficIsLoggedOnePerLineAndRotatedDaily(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	log := &TrafficLog{Path: filepath.Join(dir, "traffic.jsonl"), now: func() time.Time { return now }}
	tb := Table{Traffic: log, Units: func(d time.Duration) (float64, bool) { return d.Seconds() * 1000, true }}
	tb.add(Statement{At: now, Database: "shop", Role: "app", SQL: "select * from orders where id = 1", Took: 20 * time.Millisecond, Rows: 1})
	tb.add(Statement{At: now, Database: "shop", Role: "app", SQL: "drop table orders", Code: "42501", Rejected: true})

	recs, err := ReadTraffic(log.Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].Query != "select * from orders where id = $1" || recs[0].Units != 20 || recs[0].Rows != 1 ||
		!recs[1].Rejected || recs[1].Code != "42501" || recs[1].Tenant != "app" {
		t.Fatalf("read back %+v; want both statements with their numbers", recs)
	}

	// A day on, the file moves aside and a new one starts.
	now = now.Add(25 * time.Hour)
	tb.add(Statement{At: now, Database: "shop", Role: "app", SQL: "select 1"})
	if old, err := ReadTraffic(log.Path + ".1"); err != nil || len(old) != 2 {
		t.Errorf("rotated file has %d records, %v; want the first 2", len(old), err)
	}
	if recent, err := ReadTraffic(log.Path); err != nil || len(recent) != 1 {
		t.Errorf("new file has %d records, %v; want 1", len(recent), err)
	}
	log.Close()
}

func TestKeepsNoStatementTextOnceAdded(t *testing.T) {
	table := &Table{}
	sql := "insert into notes values ('" + strings.Repeat("x", 100_000) + "')"
	freed := make(chan struct{})
	runtime.AddCleanup(unsafe.StringData(sql), func(chan struct{}) { close(freed) }, freed)

	table.add(Statement{Database: "shop", Role: "app", SQL: sql, Took: time.Millisecond, Rows: 1})
	sql = ""

	// A big batch insert's text, kept for each statement seen, would hold gigabytes.
	defer runtime.KeepAlive(table)
	for range 10 {
		runtime.GC()
		select {
		case <-freed:
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Error("the statement's text is still held after it was added")
}
