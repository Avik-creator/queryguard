package stats

import (
	"math"
	"testing"
	"testing/synctest"
	"time"
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
