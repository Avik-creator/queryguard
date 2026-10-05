package compat

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Avik-creator/queryguard/pkg/plan"
	"github.com/Avik-creator/queryguard/pkg/policy"
	"github.com/Avik-creator/queryguard/pkg/proxy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// rulesConfig blocks UPDATE and DELETE without WHERE and only logs DDL, so tests can still make temp tables.
const rulesConfig = `{"rules": [{"check": "require_where"}, {"check": "deny_ddl", "mode": "warn"}]}`

// blockedDelete makes a statement fail in Postgres with 42P01 if the proxy ever lets it through.
const blockedDelete = "delete from qg_no_such_table"

func TestPgxRejectedStatementLeavesConnectionUsable(t *testing.T) {
	conn := startRulesProxy(t, io.Discard).connect(t, "sslmode=disable")
	for _, mode := range []pgx.QueryExecMode{pgx.QueryExecModeCacheStatement, pgx.QueryExecModeExec, pgx.QueryExecModeSimpleProtocol} {
		_, err := conn.Exec(t.Context(), blockedDelete, mode)

		expectRejected(t, mode.String(), err)
		expectSelectOne(t, conn)
	}
}

func TestPgxRejectionInTransactionFailsIt(t *testing.T) {
	conn := startRulesProxy(t, io.Discard).connect(t, "sslmode=disable")
	ctx := t.Context()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}

	_, err = tx.Exec(ctx, blockedDelete)

	expectRejected(t, "in transaction", err)
	if _, err := tx.Exec(ctx, "select 1"); sqlState(err) != "25P02" {
		t.Errorf("next statement got %v; want 25P02 in_failed_sql_transaction", err)
	}
	if err := tx.Commit(ctx); !errors.Is(err, pgx.ErrTxCommitRollback) {
		t.Errorf("COMMIT got %v; want it to roll back", err)
	}
	expectSelectOne(t, conn)
}

func TestPgxRejectionInPipelineRollsBackEarlierStatements(t *testing.T) {
	conn := startRulesProxy(t, io.Discard).connect(t, "sslmode=disable")
	ctx := t.Context()
	if _, err := conn.Exec(ctx, "create temp table qg_pipeline (id int)"); err != nil {
		t.Fatal(err)
	}

	// One Sync covers both statements, so Postgres runs them in one implicit transaction.
	p := conn.PgConn().StartPipeline(ctx)
	p.SendQueryParams("insert into qg_pipeline values (1)", nil, nil, nil, nil)
	p.SendQueryParams("delete from qg_pipeline", nil, nil, nil, nil)
	p.SendPipelineSync()
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	err := p.Close()

	expectRejected(t, "pipeline", err)
	var rows int
	if err := conn.QueryRow(ctx, "select count(*) from qg_pipeline").Scan(&rows); err != nil || rows != 0 {
		t.Errorf("table has %d rows, %v; want the insert rolled back with the rejected delete", rows, err)
	}
}

func TestWarnModeLogsWouldBeRejection(t *testing.T) {
	var logs lockedBuffer
	conn := startRulesProxy(t, &logs).connect(t, "sslmode=disable")

	if _, err := conn.Exec(t.Context(), "create temp table qg_warned (id int)"); err != nil {
		t.Fatalf("warn mode blocked DDL: %v", err)
	}

	if got := logs.String(); !strings.Contains(got, `msg="would reject statement"`) || !strings.Contains(got, "rule=deny_ddl") {
		t.Errorf("log %q; want the would-be rejection", got)
	}
}

func TestConnectionCap(t *testing.T) {
	qg := startProxyWith(t, func(s *proxy.Server) { s.Policy = mustPolicy(t, `{"max_connections": 1}`) })
	qg.connect(t, "sslmode=disable")

	_, err := pgx.Connect(t.Context(), "host=127.0.0.1 port="+port(qg)+" user=postgres dbname=queryguard sslmode=disable password="+password())

	if sqlState(err) != "53300" {
		t.Errorf("second connection got %v; want 53300 too_many_connections", err)
	}
}

func TestWrongPasswordIsRefusedQuietly(t *testing.T) {
	var logs lockedBuffer
	qg := startRulesProxy(t, &logs)

	_, err := pgx.Connect(t.Context(), "host=127.0.0.1 port="+port(qg)+" user=postgres dbname=queryguard sslmode=disable password=wrong")

	if sqlState(err) != "28P01" {
		t.Errorf("got %v; want 28P01 invalid_password", err)
	}
	if got := logs.String(); got != "" {
		t.Errorf("proxy logged %q; want nothing", got)
	}
}

// costConfig sets both cost rules at half of what a full read of orders takes, whatever the size of the test data, so
// such a read is blocked while index lookups and full reads of the 100-row tenants stay well under both limits.
func costConfig(t testing.TB) string {
	t.Helper()
	conn := connectTo(t, os.Getenv("QG_TEST_UPSTREAM"), "sslmode=disable")
	var out string
	var rows float64
	if err := conn.QueryRow(t.Context(), "explain (format json) select count(*) from orders where note = 'x'").Scan(&out); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(t.Context(), "select reltuples from pg_class where oid = 'orders'::regclass").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	p, err := plan.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if p.Cost/2 < 20 || rows/2 < 200 {
		t.Fatalf("orders is too small for the cost tests: a full read costs %.0f and it has %.0f rows", p.Cost, rows)
	}
	return fmt.Sprintf(`{"rules": [{"check": "max_cost", "cost": %.0f}, {"check": "max_scan_rows", "rows": %.0f}]}`, p.Cost/2, rows/2)
}

func TestPgxCostRules(t *testing.T) {
	conn := startCostProxy(t, nil).connect(t, "sslmode=disable")
	for _, mode := range []pgx.QueryExecMode{pgx.QueryExecModeCacheStatement, pgx.QueryExecModeExec, pgx.QueryExecModeSimpleProtocol} {
		for _, tc := range []struct {
			sql  string
			arg  any
			want string // the rule that blocks it
		}{
			{"select id from orders where id = $1", 7, ""},
			{"select count(*) from orders where note = $1", "x", "max_cost"},
			// Cheap, but it starts a full read of orders that a WHERE clause would turn into a slow one.
			{"select * from orders where total_cents > $1 limit 1", 0, "max_scan_rows"},
			{"select * from tenants where name <> $1", "x", ""},
		} {
			_, err := conn.Exec(t.Context(), tc.sql, mode, tc.arg)
			if tc.want == "" {
				if err != nil {
					t.Errorf("%s: %s failed: %v", mode, tc.sql, err)
				}
				continue
			}
			if pgErr, ok := errors.AsType[*pgconn.PgError](err); !ok || pgErr.Code != "54000" || !strings.Contains(pgErr.Message, tc.want) {
				t.Errorf("%s: %s got %v; want 54000 from %s", mode, tc.sql, err, tc.want)
			}
			expectSelectOne(t, conn)
		}
	}
}

func TestCostRulesJudgeEachValue(t *testing.T) {
	conn := startCostProxy(t, nil).connect(t, "sslmode=disable")
	for _, mode := range []pgx.QueryExecMode{pgx.QueryExecModeCacheStatement, pgx.QueryExecModeExec, pgx.QueryExecModeSimpleProtocol} {
		// Few orders are pending, read through a small partial index; most are delivered, which reads the whole table.
		if _, err := conn.Exec(t.Context(), "select count(*) from orders where status = $1", mode, "pending"); err != nil {
			t.Fatalf("%s: rare status failed: %v", mode, err)
		}
		_, err := conn.Exec(t.Context(), "select count(*) from orders where status = $1", mode, "delivered")
		if sqlState(err) != "54000" {
			t.Errorf("%s: common status after a rare one got %v; want 54000 from its own plan", mode, err)
		}
	}
}

func TestCostCheckPassesOnPostgresErrors(t *testing.T) {
	conn := startCostProxy(t, nil).connect(t, "sslmode=disable")
	direct := connectTo(t, os.Getenv("QG_TEST_UPSTREAM"), "sslmode=disable")
	const sql = "select id, nosuchcolumn from orders"

	_, want := direct.Exec(t.Context(), sql, pgx.QueryExecModeSimpleProtocol)
	_, got := conn.Exec(t.Context(), sql, pgx.QueryExecModeSimpleProtocol)

	// The client sees the error its own statement would get, pointing into its own text.
	wantErr, _ := errors.AsType[*pgconn.PgError](want)
	gotErr, ok := errors.AsType[*pgconn.PgError](got)
	if !ok || wantErr == nil || gotErr.Code != wantErr.Code || gotErr.Position != wantErr.Position {
		t.Errorf("through the proxy: %v at %d; straight to Postgres: %v at %d", got, gotErr.Position, want, wantErr.Position)
	}
	expectSelectOne(t, conn)
}

func TestPgxCostRejectionInTransactionFailsIt(t *testing.T) {
	conn := startCostProxy(t, nil).connect(t, "sslmode=disable")
	ctx := t.Context()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}

	_, err = tx.Exec(ctx, "select count(*) from orders where note = $1", "x")

	if sqlState(err) != "54000" {
		t.Errorf("costly statement got %v; want 54000", err)
	}
	if _, err := tx.Exec(ctx, "select 1"); sqlState(err) != "25P02" {
		t.Errorf("next statement got %v; want 25P02 in_failed_sql_transaction", err)
	}
	tx.Rollback(ctx)
	expectSelectOne(t, conn)
}

func TestPlanCacheServesRepeatedStatements(t *testing.T) {
	var s *proxy.Server
	conn := startCostProxy(t, func(srv *proxy.Server) {
		srv.Plans.RefreshOneIn = -1
		s = srv
	}).connect(t, "sslmode=disable")

	// Cost rules that block judge each value's own plan, so only a repeated value hits the cache.
	for range 5 {
		var got int64
		if err := conn.QueryRow(t.Context(), "select id from orders where id = $1", 7).Scan(&got); err != nil {
			t.Fatal(err)
		}
	}

	if st := s.PlanStats(); st.Misses != 1 || st.Hits != 4 {
		t.Errorf("plan cache %+v; want 1 miss and 4 hits", st)
	}
}

func TestCatalogReadsTableSizes(t *testing.T) {
	c := &plan.Catalog{DSN: catalogDSN(t)}
	var want float64
	direct := connectTo(t, os.Getenv("QG_TEST_UPSTREAM"), "sslmode=disable")
	if err := direct.QueryRow(t.Context(), "select reltuples from pg_class where oid = 'orders'::regclass").Scan(&want); err != nil {
		t.Fatal(err)
	}

	rows, ok := c.Rows("queryguard", plan.Table{Schema: "public", Name: "orders"})

	if !ok || rows != want || rows <= 0 {
		t.Errorf("orders has %v rows (%v); want pg_class's %v", rows, ok, want)
	}
}

func TestCatalogSeesStaleStatistics(t *testing.T) {
	dsn := catalogDSN(t)
	direct := connectTo(t, os.Getenv("QG_TEST_UPSTREAM"), "sslmode=disable")
	name := fmt.Sprintf("qg_stale_%d", time.Now().UnixNano())
	t.Cleanup(func() { direct.Exec(context.Background(), "drop table "+name) })
	// Autovacuum would analyze the table again before the test looks.
	mustExec(t, direct, "create table "+name+" (id int) with (autovacuum_enabled = false)")
	// A session reports its changes at most once a second, as it goes idle; forcing it makes them count before the next step.
	insert := func() {
		mustExec(t, direct, "insert into "+name+" select generate_series(1, 1000)")
		mustExec(t, direct, "select pg_stat_force_next_flush()")
	}
	insert()
	mustExec(t, direct, "analyze "+name)
	table := plan.Table{Schema: "public", Name: name}
	fresh := &plan.Catalog{DSN: dsn}
	if _, ok := fresh.Rows("queryguard", table); !ok || fresh.Stale("queryguard", table) {
		t.Fatal("a table just analyzed is stale, or has no size")
	}

	insert()

	stale := &plan.Catalog{DSN: dsn}
	stale.Rows("queryguard", table)
	if !stale.Stale("queryguard", table) {
		t.Error("a table that doubled since it was analyzed is not stale")
	}
}

func TestMonitorSeesLockWaitsAndTheOldestSnapshot(t *testing.T) {
	dsn := catalogDSN(t) + " dbname=queryguard"
	upstream := os.Getenv("QG_TEST_UPSTREAM")
	holder, locker, waiter, setup := connectTo(t, upstream, "sslmode=disable"), connectTo(t, upstream, "sslmode=disable"),
		connectTo(t, upstream, "sslmode=disable"), connectTo(t, upstream, "sslmode=disable")
	name := fmt.Sprintf("qg_monitor_%d", time.Now().UnixNano())
	mustExec(t, setup, "create table "+name+" (id int)")
	t.Cleanup(func() { setup.Exec(context.Background(), "drop table "+name) })
	holderPID, lockerPID, waiterPID := pidOf(t, holder), pidOf(t, locker), pidOf(t, waiter)

	// holder's snapshot predates an assigned transaction ID, so it is the oldest.
	mustExec(t, holder, "begin isolation level repeatable read")
	mustExec(t, holder, "select 1")
	mustExec(t, setup, "select txid_current()")
	mustExec(t, locker, "begin")
	mustExec(t, locker, "lock table "+name+" in access exclusive mode")
	waited := make(chan error, 1)
	go func() {
		_, err := waiter.Exec(context.Background(), "select * from "+name)
		waited <- err
	}()
	t.Cleanup(func() {
		locker.Exec(context.Background(), "rollback")
		<-waited
	})

	table := plan.Table{Schema: "public", Name: name}
	m := &plan.Monitor{DSN: dsn, Interval: 100 * time.Millisecond, Watch: func() []plan.Table { return []plan.Table{table} }}
	ctx, stop := context.WithCancel(t.Context())
	defer stop()
	seen := make(chan plan.Activity, 100)
	go m.Run(ctx, func(a plan.Activity) {
		if len(a.Waiting) > 0 {
			select {
			case seen <- a:
			default:
			}
		}
	})
	var a plan.Activity
	select {
	case a = <-seen:
	case <-time.After(10 * time.Second):
		t.Fatal("the monitor saw no lock wait in 10s")
	}

	w, ok := a.Waiting[waiterPID]
	if !ok || !slices.Contains(w.Blockers, lockerPID) {
		t.Errorf("waiting %+v; want the waiter, blocked by the locker", a.Waiting)
	}
	if a.Horizon.PID != holderPID || a.Horizon.Age <= 0 {
		t.Errorf("horizon %+v; want the repeatable read transaction's backend", a.Horizon)
	}
	if _, ok := a.DeadTuples[table]; !ok {
		t.Errorf("dead tuples %v; want the watched table", a.DeadTuples)
	}
	if a.ReplicationLag != 0 {
		t.Errorf("replication lag %v; want 0 without standbys", a.ReplicationLag)
	}
}

func TestDDLStuckBehindALongTransactionIsCancelled(t *testing.T) {
	dsn := catalogDSN(t) + " dbname=queryguard"
	direct := connectTo(t, os.Getenv("QG_TEST_UPSTREAM"), "sslmode=disable")
	name := fmt.Sprintf("qg_ddl_guard_%d", time.Now().UnixNano())
	mustExec(t, direct, "create table "+name+" (id int)")
	t.Cleanup(func() { direct.Exec(context.Background(), "drop table "+name) })
	// A long transaction holds a lock on the table that ALTER TABLE must wait for.
	mustExec(t, direct, "begin")
	mustExec(t, direct, "select * from "+name)
	t.Cleanup(func() { direct.Exec(context.Background(), "rollback") })

	var logs lockedBuffer
	qg := startProxyWith(t, func(s *proxy.Server) {
		s.Policy = mustPolicy(t, `{}`)
		s.Monitor = &plan.Monitor{DSN: dsn, Interval: 100 * time.Millisecond}
		s.Logger = slog.New(slog.NewTextHandler(io.MultiWriter(&logs, t.Output()), nil))
	})
	migrator, reader := qg.connect(t, "sslmode=disable"), qg.connect(t, "sslmode=disable")
	altered := make(chan error, 1)
	go func() {
		_, err := migrator.Exec(context.Background(), "alter table "+name+" add column note text")
		altered <- err
	}()
	time.Sleep(50 * time.Millisecond)

	// The read queues behind the ALTER's lock request, so the ALTER is cancelled and the read runs.
	start := time.Now()
	if _, err := reader.Exec(t.Context(), "select count(*) from "+name); err != nil {
		t.Fatalf("read behind the ALTER: %v", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("the read waited %v; want the ALTER cancelled within a second or so", took)
	}
	if err := <-altered; sqlState(err) != "55P03" {
		t.Errorf("ALTER got %v; want 55P03 lock_not_available", err)
	}
	if !strings.Contains(logs.String(), "cancelled DDL waiting on a lock") {
		t.Errorf("log %q; want the cancel", logs.String())
	}
	expectSelectOne(t, migrator)
}

// pidOf returns conn's backend process ID.
func pidOf(t testing.TB, conn *pgx.Conn) int32 {
	t.Helper()
	var pid int32
	if err := conn.QueryRow(t.Context(), "select pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	return pid
}

func TestBudgetRejectsTenantThatSpentIt(t *testing.T) {
	// Each statement costs at least 100 units, and 250 are saved up, so the fourth finds the budget spent.
	conn := startPolicyProxy(t, `{"tenants": {"postgres": {"budget": {"rate": 1, "burst": 250, "min_charge": 100, "when_over": "reject"}}}}`).
		connect(t, "sslmode=disable")

	var codes []string
	for range 4 {
		_, err := conn.Exec(t.Context(), "select id from orders where id = $1", 7)
		codes = append(codes, sqlState(err))
	}

	if !slices.Equal(codes, []string{"", "", "", "53000"}) {
		t.Errorf("SQLSTATEs %q; want the fourth statement rejected with 53000", codes)
	}
}

func TestBudgetQueuesUntilRefilled(t *testing.T) {
	conn := startPolicyProxy(t, `{"tenants": {"postgres": {"budget": {"rate": 100, "burst": 100, "min_charge": 150}}}}`).
		connect(t, "sslmode=disable")
	expectSelectOne(t, conn)

	// The first statement left 50 units owed, which take half a second to come back.
	start := time.Now()
	expectSelectOne(t, conn)

	if waited := time.Since(start); waited < 400*time.Millisecond || waited > 2*time.Second {
		t.Errorf("second statement took %v; want about 500ms in the queue", waited)
	}
}

func TestStatementTimeoutCancelsStatement(t *testing.T) {
	conn := startPolicyProxy(t, `{"tenant_defaults": {"statement_timeout": "300ms"}}`).connect(t, "sslmode=disable")

	start := time.Now()
	_, err := conn.Exec(t.Context(), "select pg_sleep(10)")

	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	if !ok || pgErr.Code != "57014" || !strings.Contains(pgErr.Message, "statement timeout") {
		t.Fatalf("pg_sleep(10) ended with %v; want 57014 from the statement timeout", err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("cancel took %v", took)
	}
	expectSelectOne(t, conn)
}

func TestIdleInTransactionEndsSession(t *testing.T) {
	conn := startPolicyProxy(t, `{"tenant_defaults": {"idle_in_transaction_timeout": "300ms"}}`).connect(t, "sslmode=disable")
	ctx := t.Context()
	if _, err := conn.Exec(ctx, "begin"); err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Second)

	if _, err := conn.Exec(ctx, "select 1"); err == nil {
		t.Error("a statement ran in a transaction left idle past its limit")
	}
}

func TestCancelsQueryWhenClientVanishes(t *testing.T) {
	// With Postgres's own socket check off, only the proxy's CancelRequest can stop the query quickly.
	qg := startProxyWith(t, func(s *proxy.Server) { s.ClientCheckInterval = 0 })
	app := fmt.Sprintf("qg_vanish_%d", time.Now().UnixNano())
	victim := qg.connect(t, "sslmode=disable application_name="+app)
	watcher := qg.connect(t, "sslmode=disable")
	running := make(chan struct{})
	go func() {
		defer close(running)
		victim.Exec(t.Context(), "select pg_sleep(30)")
	}()
	waitFor(t, 5*time.Second, func() bool { return activeQueries(t, watcher, app) == 1 })

	victim.PgConn().Conn().Close()
	<-running

	waitFor(t, 2*time.Second, func() bool { return activeQueries(t, watcher, app) == 0 })
}

func TestTenantTagFromTrustedRole(t *testing.T) {
	conn := startPolicyProxy(t, `{"trusted_roles": ["postgres"], "rules": [{"check": "require_where", "match": {"tenants": ["acme"]}}]}`).
		connect(t, "sslmode=disable")

	_, acme := conn.Exec(t.Context(), "delete from qg_no_such_table /*tenant='acme'*/")
	_, other := conn.Exec(t.Context(), "delete from qg_no_such_table /*tenant='other'*/")

	// Only acme's rule applies, so other's statement reaches Postgres and fails there.
	if sqlState(acme) != "42501" || sqlState(other) != "42P01" {
		t.Errorf("acme got %v and other got %v; want 42501 and 42P01", acme, other)
	}
}

func TestBusyWhenNoSlotComesFree(t *testing.T) {
	qg := startPolicyProxy(t, `{"scheduler": {"max_active": 1, "queue_timeout": "300ms"}}`)
	holder, waiter := qg.connect(t, "sslmode=disable"), qg.connect(t, "sslmode=disable")
	// The holder's statement ends before the test closes its connection, which pgx can't use from two goroutines.
	var holding sync.WaitGroup
	defer holding.Wait()
	holding.Go(func() { holder.Exec(context.Background(), "select pg_sleep(1)") })
	time.Sleep(300 * time.Millisecond)

	_, err := waiter.Exec(t.Context(), "select 1")

	if sqlState(err) != "53000" {
		t.Errorf("statement with the only slot taken got %v; want 53000", err)
	}
}

func TestDroppedIndexGoesToSlowLane(t *testing.T) {
	var logs lockedBuffer
	conn := startFlipProxy(t, &logs).connect(t, "sslmode=disable")
	mustExec(t, conn, "create temp table qg_flip as select g as id, md5(g::text) as note from generate_series(1, 200000) g")
	mustExec(t, conn, "alter table qg_flip add primary key (id)")
	mustExec(t, conn, "analyze qg_flip")
	lookup := func(id int) {
		var note string
		if err := conn.QueryRow(t.Context(), "select note from qg_flip where id = $1", id).Scan(&note); err != nil {
			t.Fatal(err)
		}
	}
	for id := range 5 {
		lookup(id + 1)
	}

	// Dropping the index through the proxy makes it explain the lookup again before it next runs.
	mustExec(t, conn, "alter table qg_flip drop constraint qg_flip_pkey")
	lookup(6)

	if got := logs.String(); !strings.Contains(got, `msg="plan flip"`) || !strings.Contains(got, "in full") || !strings.Contains(got, "slow_lane=true") {
		t.Errorf("log %q; want the full read flagged as a plan flip and run in the slow lane", got)
	}
}

func TestForcedGenericPlanGoesToSlowLane(t *testing.T) {
	var logs lockedBuffer
	conn := startFlipProxy(t, &logs).connect(t, "sslmode=disable")
	// Forty rows in four million are rare: the plan for 'rare' uses the index, while one for any value reads the table in
	// full, comparing every row's kind, which takes well over the 100ms a slow run needs, even on a fast machine.
	mustExec(t, conn, "create temp table qg_skew as select g as id, case when g % 100000 = 0 then 'rare' else 'common' end as kind "+
		"from generate_series(1, 4000000) g")
	mustExec(t, conn, "create index on qg_skew (kind)")
	// ANALYZE reads every row, so it always finds the rare value, and the column is said to hold one value, as a sample of it
	// usually says, so a plan for any value expects nearly every row.
	mustExec(t, conn, "alter table qg_skew alter column kind set statistics 10000, alter column kind set (n_distinct = 1)")
	mustExec(t, conn, "analyze qg_skew")
	count := func() {
		var n int
		if err := conn.QueryRow(t.Context(), "select count(*) from qg_skew where kind = $1", "rare").Scan(&n); err != nil || n != 40 {
			t.Fatalf("count = %d, %v; want 40", n, err)
		}
	}
	for range 5 {
		count()
	}

	// The proxy explains with the bound value, so only the time the generic plan takes gives it away.
	mustExec(t, conn, "set plan_cache_mode = force_generic_plan")
	count()
	count()

	if got := logs.String(); !strings.Contains(got, `msg="plan flip"`) || !strings.Contains(got, "slow_lane=true") {
		t.Errorf("log %q; want the generic plan's run flagged and the next one run in the slow lane", got)
	}
}

// startFlipProxy starts a proxy whose statements are explained for slots, logging to logs.
func startFlipProxy(t testing.TB, logs io.Writer) *queryGuard {
	t.Helper()
	return startProxyWith(t, func(s *proxy.Server) {
		s.Policy = mustPolicy(t, `{"scheduler": {"max_active": 10, "slow_lane": {"max_active": 2}}}`)
		s.Plans.RefreshOneIn = -1
		s.Logger = slog.New(slog.NewTextHandler(io.MultiWriter(logs, t.Output()), nil))
	})
}

func mustExec(t testing.TB, conn *pgx.Conn, sql string) {
	t.Helper()
	if _, err := conn.Exec(t.Context(), sql); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// startPolicyProxy starts a proxy with config.
func startPolicyProxy(t testing.TB, config string) *queryGuard {
	t.Helper()
	return startProxyWith(t, func(s *proxy.Server) { s.Policy = mustPolicy(t, config) })
}

// startCostProxy starts a proxy with costConfig and a catalog, letting configure see the server too.
func startCostProxy(t testing.TB, configure func(*proxy.Server)) *queryGuard {
	t.Helper()
	return startProxyWith(t, func(s *proxy.Server) {
		s.Policy = mustPolicy(t, costConfig(t))
		s.Catalog = &plan.Catalog{DSN: catalogDSN(t)}
		if configure != nil {
			configure(s)
		}
	})
}

// catalogDSN connects straight to QG_TEST_UPSTREAM as the docker compose superuser.
func catalogDSN(t testing.TB) string {
	t.Helper()
	host, port, err := net.SplitHostPort(os.Getenv("QG_TEST_UPSTREAM"))
	if err != nil {
		t.Skip("set QG_TEST_UPSTREAM to a Postgres host:port")
	}
	return fmt.Sprintf("host=%s port=%s user=postgres password=%s sslmode=disable", host, port, password())
}

// startRulesProxy starts a proxy with rulesConfig that logs to logs.
func startRulesProxy(t testing.TB, logs io.Writer) *queryGuard {
	t.Helper()
	return startProxyWith(t, func(s *proxy.Server) {
		s.Policy = mustPolicy(t, rulesConfig)
		s.Logger = slog.New(slog.NewTextHandler(io.MultiWriter(logs, t.Output()), nil))
	})
}

func mustPolicy(t testing.TB, config string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(config))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func expectRejected(t *testing.T, what string, err error) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" || !strings.Contains(pgErr.Message, "require_where") {
		t.Errorf("%s: got %v; want 42501 from rule require_where", what, err)
	}
}

func expectSelectOne(t *testing.T, conn *pgx.Conn) {
	t.Helper()
	var one int
	if err := conn.QueryRow(t.Context(), "select 1").Scan(&one); err != nil || one != 1 {
		t.Errorf("select 1 after the rejection = %d, %v", one, err)
	}
}

func sqlState(err error) string {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		return pgErr.Code
	}
	return ""
}

func port(qg *queryGuard) string {
	_, p, _ := strings.Cut(qg.addr, ":")
	return p
}

// lockedBuffer is a bytes.Buffer that session goroutines can log to while the test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
