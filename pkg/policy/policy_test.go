package policy

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Avik-creator/queryguard/pkg/plan"
	"github.com/Avik-creator/queryguard/pkg/sched"
	"github.com/Avik-creator/queryguard/pkg/session"
	"github.com/Avik-creator/queryguard/pkg/sqlparse"
	"github.com/jackc/pgx/v5/pgproto3"
)

const allRules = `{"rules": [
	{"check": "deny_ddl"},
	{"check": "require_where"},
	{"check": "index_concurrently"},
	{"check": "schema_allowlist", "schemas": ["public"]}
]}`

func TestRulesBlockStatements(t *testing.T) {
	c := mustParse(t, allRules).Checker("alice", discard)
	for sql, rule := range map[string]string{
		"select * from orders where id = 1":                                    "",
		"update orders set total = 0 where id = 1":                             "",
		"select * from pg_catalog.pg_class":                                    "",
		"select * from information_schema.tables":                              "",
		"select * from public.orders":                                          "",
		"create table notes (id int)":                                          "deny_ddl",
		"do $$ begin perform 1; end $$":                                        "deny_ddl",
		"call purge_orders()":                                                  "deny_ddl",
		"delete from orders":                                                   "require_where",
		"select 1; update orders set total = 0":                                "require_where",
		"select * from billing.invoices":                                       "schema_allowlist",
		"set search_path to billing":                                           "schema_allowlist",
		"truncate orders":                                                      "require_where",
		"select * from pg_temp_3.scratch":                                      "",
		"drop table billing.invoices":                                          "deny_ddl",
		"select set_config('search_path', 'billing', false)":                   "schema_allowlist",
		"select set_config('search_path', current_setting('app.path'), false)": "schema_allowlist",
		"create index concurrently on orders (customer_id)":                    "deny_ddl",
		"create index on billing.orders (customer_id)":                         "deny_ddl",
		"create unique index on orders (id) where id > 1000":                   "deny_ddl",
	} {
		got := rejected(c.Check(sql, standard))
		if gotRule := ruleOf(got); gotRule != rule {
			t.Errorf("Check(%q) blocked by %q; want %q", sql, gotRule, rule)
		}
	}
}

func TestIndexConcurrentlyRule(t *testing.T) {
	c := mustParse(t, `{"rules": [{"check": "index_concurrently"}]}`).Checker("alice", discard)
	for sql, blocked := range map[string]bool{
		"create index on orders (customer_id)":              true,
		"create index concurrently on orders (customer_id)": false,
		"create index on only events (customer_id)":         false,
		"drop index orders_customer_idx":                    true,
		"drop index concurrently orders_customer_idx":       false,
		"reindex table orders":                              true,
		"reindex table concurrently orders":                 false,
	} {
		if got := rejected(c.Check(sql, standard)); (ruleOf(got) == "index_concurrently") != blocked {
			t.Errorf("Check(%q) = %v; want blocked = %v", sql, got, blocked)
		}
	}
}

func TestRejectionCarriesOnlyFixedTextAndFingerprint(t *testing.T) {
	c := mustParse(t, allRules).Checker("alice", discard)

	got := rejected(c.Check("delete from orders -- it's O'Brien's", standard))

	if got == nil {
		t.Fatal("DELETE without WHERE was allowed")
	}
	if got.Severity != "ERROR" || got.Code != "42501" {
		t.Errorf("got %s %s; want ERROR 42501", got.Severity, got.Code)
	}
	if !strings.Contains(got.Detail, "fingerprint") || !strings.Contains(got.Detail, sqlparse.Fingerprint("delete from orders")) {
		t.Errorf("detail %q; want the statement fingerprint", got.Detail)
	}
	for _, text := range []string{got.Message, got.Detail, got.Hint} {
		if strings.ContainsAny(text, `'\$`) || strings.Contains(text, "orders") {
			t.Errorf("error text %q carries client text or quoting characters", text)
		}
	}
}

func TestWarnModeLogsAndAllows(t *testing.T) {
	var logs bytes.Buffer
	c := mustParse(t, `{"rules": [{"check": "require_where", "mode": "warn"}]}`).Checker("alice", logger(&logs))

	if got := rejected(c.Check("delete from orders where false; delete from orders", standard)); got != nil {
		t.Errorf("warn mode rejected with %v; want allowed", got)
	}
	for _, want := range []string{`msg="would reject statement"`, "rule=require_where", "role=alice", "fingerprint=", "delete from orders where $1"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log %q lacks %q", logs.String(), want)
		}
	}
}

func TestEnforceModeLogs(t *testing.T) {
	var logs bytes.Buffer
	c := mustParse(t, allRules).Checker("alice", logger(&logs))

	rejected(c.Check("delete from orders", standard))

	if !strings.Contains(logs.String(), `msg="rejected statement"`) || !strings.Contains(logs.String(), "rule=require_where") {
		t.Errorf("log %q; want the rejection", logs.String())
	}
}

func TestTenantInWarnModeIsNeverBlocked(t *testing.T) {
	p := mustParse(t, `{"rules": [{"check": "require_where"}], "tenants": {"reporting": {"mode": "warn"}}}`)

	if got := rejected(p.Checker("reporting", discard).Check("delete from orders", standard)); got != nil {
		t.Errorf("tenant in warn mode got %v; want allowed", got)
	}
	if got := rejected(p.Checker("alice", discard).Check("delete from orders", standard)); got == nil {
		t.Error("other tenants were not blocked")
	}
}

func TestUncheckedStatements(t *testing.T) {
	for config, wantReject := range map[string]bool{
		`{"rules": [{"check": "require_where"}]}`:                        true,
		`{"rules": [{"check": "require_where"}], "unchecked": "allow"}`:  false,
		`{"rules": [{"check": "require_where"}], "unchecked": "reject"}`: true,
		`{"unchecked": "reject"}`:                                        false,
	} {
		var logs bytes.Buffer
		c := mustParse(t, config).Checker("alice", logger(&logs))

		got := rejected(c.Check("selec 1", standard))

		if (got != nil) != wantReject {
			t.Errorf("%s: unparsable statement got %v; want rejected = %v", config, got, wantReject)
		}
		if got != nil && got.Code != "42501" {
			t.Errorf("%s: got code %s; want 42501", config, got.Code)
		}
		if strings.Contains(config, "rules") && !strings.Contains(logs.String(), "could not check statement") {
			t.Errorf("%s: log %q; want the parse failure", config, logs.String())
		}
	}
}

func TestStatementTooLongToCheck(t *testing.T) {
	allow := mustParse(t, `{"rules": [{"check": "require_where"}], "unchecked": "allow"}`).Checker("alice", discard)
	reject := mustParse(t, `{"rules": [{"check": "require_where"}]}`).Checker("alice", discard)

	if got := allow.CheckTooLong(1 << 30); got != nil {
		t.Errorf("unchecked allow got %v; want allowed", got)
	}
	if got := reject.CheckTooLong(1 << 30); got == nil || got.Code != "42501" {
		t.Errorf("unchecked reject got %v; want 42501", got)
	}
}

func TestStatementPostgresMayReadDifferently(t *testing.T) {
	unknown := session.Settings{}
	scsOff := session.Settings{StandardConformingStrings: "off", ClientEncoding: "UTF8"}
	sjis := session.Settings{StandardConformingStrings: "on", ClientEncoding: "SJIS"}
	sqlASCII := session.Settings{StandardConformingStrings: "on", ClientEncoding: "SQL_ASCII"}
	for _, tc := range []struct {
		set  session.Settings
		sql  string
		want bool // rejected as unchecked
	}{
		{standard, `select '\''; delete from orders; --'`, false},
		{scsOff, `select '\''; delete from orders; --'`, true},
		{standard, `select 'a\b'`, false},
		{scsOff, `select 'a\b'`, true},
		{scsOff, `select E'a\b', $$\$$`, false},
		{scsOff, `select 1`, false},
		{unknown, `select 'a\b'`, true},
		{unknown, `select 'ok'`, false},
		{sjis, `select 'ü'`, true},
		{sjis, `select 'u'`, false},
		{unknown, `select 'ü'`, true},
		{standard, `select 'ü'`, false},
		{sqlASCII, `select 'ü'`, false},
	} {
		var logs bytes.Buffer
		c := mustParse(t, `{"rules": [{"check": "require_where"}]}`).Checker("alice", logger(&logs))

		got := rejected(c.Check(tc.sql, tc.set))

		// A quote hidden behind a backslash makes the first statement look like one SELECT; it is rejected unchecked, not by a rule.
		if unchecked := got != nil && got.Message == "queryguard: statement could not be checked"; unchecked != tc.want {
			t.Errorf("Check(%q, %+v) = %v; want unchecked = %v", tc.sql, tc.set, got, tc.want)
		}
		if tc.want && !strings.Contains(logs.String(), "could not check statement") {
			t.Errorf("Check(%q, %+v) logged %q; want the reason", tc.sql, tc.set, logs.String())
		}
	}
}

func TestStartupSearchPath(t *testing.T) {
	c := mustParse(t, allRules).Checker("alice", discard)
	for _, tc := range []struct {
		settings map[string]string
		want     string // the rule that refuses the login
	}{
		{map[string]string{"search_path": "public, pg_catalog"}, ""},
		{map[string]string{"application_name": "billing"}, ""},
		{map[string]string{"search_path": "billing"}, "schema_allowlist"},
		{map[string]string{"search_path": `public, "Billing"`}, "schema_allowlist"},
	} {
		got := c.CheckStartup(maps.All(tc.settings))
		if ruleOf(got) != tc.want {
			t.Errorf("CheckStartup(%v) = %v; want blocked by %q", tc.settings, got, tc.want)
		}
		if got != nil && (got.Severity != "FATAL" || got.Code != "42501") {
			t.Errorf("CheckStartup(%v) = %s %s; want FATAL 42501", tc.settings, got.Severity, got.Code)
		}
	}
	warn := mustParse(t, `{"rules": [{"check": "schema_allowlist", "schemas": ["public"], "mode": "warn"}]}`).Checker("alice", discard)
	if got := warn.CheckStartup(maps.All(map[string]string{"search_path": "billing"})); got != nil {
		t.Errorf("warn mode refused the login with %v", got)
	}
}

const costRules = `{"rules": [{"check": "max_cost", "cost": 1000}, {"check": "max_scan_rows", "rows": 50000}]}`

func TestCostCheckOnlyForStatementsEXPLAINCanPlan(t *testing.T) {
	c := costChecker(t, costRules, nil, discard)
	for sql, want := range map[string]bool{
		"select * from orders":            true,
		"update orders set total = 0":     true,
		"begin":                           false,
		"select 1; select * from orders":  false,
		"create index on orders (status)": false,
	} {
		explained := false
		// DDL passes a gate too, which explains nothing but forgets cached plans once it ran.
		if _, gate := c.Check(sql, standard); gate != nil {
			gate(t.Context(), session.Explain{Run: func() (string, error) { explained = true; return orderLookup, nil }}, false)
		}
		if explained != want {
			t.Errorf("Check(%q) explained = %v; want %v", sql, explained, want)
		}
	}
	if _, cost := mustParse(t, allRules).Checker("alice", discard).Check("select * from orders", standard); cost != nil {
		t.Error("a policy without cost rules asked for a plan")
	}
}

func TestCostRules(t *testing.T) {
	big := `[{"Plan": {"Node Type": "Seq Scan", "Schema": "public", "Relation Name": "orders", "Total Cost": 900}}]`
	for name, tc := range map[string]struct {
		out  string
		want string // the rule that blocks it
	}{
		"cheap":                    {`[{"Plan": {"Node Type": "Index Scan", "Total Cost": 8.4}}]`, ""},
		"over the cost":            {`[{"Plan": {"Node Type": "Index Scan", "Total Cost": 1000.5}}]`, "max_cost"},
		"full read of a big table": {big, "max_scan_rows"},
		"full read of a small one": {`[{"Plan": {"Node Type": "Seq Scan", "Schema": "public", "Relation Name": "tenants", "Total Cost": 3}}]`, ""},
		"table never analyzed":     {`[{"Plan": {"Node Type": "Seq Scan", "Schema": "public", "Relation Name": "fresh", "Total Cost": 3}}]`, ""},
		// Partitions of 30000 rows each are small, but a plan reading two of them in full reads 60000 rows.
		"full read across partitions": {`[{"Plan": {"Node Type": "Append", "Total Cost": 900, "Plans": [
			{"Node Type": "Seq Scan", "Schema": "public", "Relation Name": "events_1", "Total Cost": 450},
			{"Node Type": "Seq Scan", "Schema": "public", "Relation Name": "events_2", "Total Cost": 450}]}}]`, "max_scan_rows"},
		"both, cost listed first": {strings.Replace(big, "900", "2000", 1), "max_cost"},
	} {
		c := costChecker(t, costRules, tables{"public.orders": 1e6, "public.tenants": 100, "public.events_1": 30000, "public.events_2": 30000}, discard)
		_, cost := c.Check("select * from orders where note = 'x'", standard)

		got := costOf(cost, explained(tc.out, nil))

		if ruleOf(got) != tc.want {
			t.Errorf("%s: blocked by %q (%v); want %q", name, ruleOf(got), got, tc.want)
		}
		if got != nil && got.Code != "54000" {
			t.Errorf("%s: code %s; want 54000 program_limit_exceeded", name, got.Code)
		}
	}
}

func TestCostRejectionCarriesNumbersNotNames(t *testing.T) {
	var logs bytes.Buffer
	c := costChecker(t, costRules, tables{"public.orders": 1e6}, logger(&logs))
	_, cost := c.Check("select * from orders where note = 'x'", standard)

	got := costOf(cost, explained(`[{"Plan": {"Node Type": "Seq Scan", "Schema": "public", "Relation Name": "orders", "Total Cost": 500}}]`, nil))

	if got == nil || !strings.Contains(got.Detail, "1000000 rows") || !strings.Contains(got.Detail, "50000") {
		t.Fatalf("got %v; want a detail with the table size and the limit", got)
	}
	if strings.Contains(got.Detail, "orders") || strings.ContainsAny(got.Detail+got.Message+got.Hint, `'\$`) {
		t.Errorf("rejection %q carries a name or quoting characters", got.Detail)
	}
	if !strings.Contains(logs.String(), "seq_scans=[public.orders]") || !strings.Contains(logs.String(), "cost=500") {
		t.Errorf("log %q; want the table and the cost", logs.String())
	}
}

func TestCostCheckUsesCachedPlans(t *testing.T) {
	for config, want := range map[string]plan.Stats{
		// Enforced cost rules judge each statement's own values, so only the same text hits the cache.
		costRules: {Hits: 1, Misses: 3},
		// Rules that only log share one plan across values, as budgets do.
		`{"rules": [{"check": "max_cost", "cost": 1000, "mode": "warn"}]}`: {Hits: 2, Misses: 2},
	} {
		c := costChecker(t, config, nil, discard)
		for _, sql := range []string{"select * from orders where id = 1", "select * from orders where id = 1", "select * from orders where id = 2"} {
			_, cost := c.Check(sql, standard)
			costOf(cost, costing(8))
		}
		// A generic plan is a different plan.
		_, cost := c.Check("select * from orders where id = 3", standard)
		costOf(cost, session.Explain{Generic: true, Run: costing(8).Run})

		if s := c.Env.Plans.Stats(); s.Hits != want.Hits || s.Misses != want.Misses {
			t.Errorf("%s: cache stats %+v; want %d hits, %d misses", config, s, want.Hits, want.Misses)
		}
	}
}

func TestEnforcedCostRulesJudgeEachValuesOwnPlan(t *testing.T) {
	c := costChecker(t, costRules, nil, discard)
	// A rare status gets an index lookup; a common one, with the same fingerprint, reads most of the table.
	if got := costOf(gateOf(t, c, "select * from orders where status = 'rare'"), costing(8)); got != nil {
		t.Fatalf("cheap statement got %v", got)
	}
	if got := costOf(gateOf(t, c, "select * from orders where status = 'common'"), costing(5000)); ruleOf(got) != "max_cost" {
		t.Errorf("costly value after a cheap one got %v; want max_cost", got)
	}

	// The same goes for a prepared statement's bound values.
	const bound = "select * from orders where status = $1"
	if got := costOf(gateOf(t, c, bound), session.Explain{Values: "rare", Run: costing(8).Run}); got != nil {
		t.Fatalf("cheap bound value got %v", got)
	}
	if got := costOf(gateOf(t, c, bound), session.Explain{Values: "common", Run: costing(5000).Run}); ruleOf(got) != "max_cost" {
		t.Errorf("costly bound value after a cheap one got %v; want max_cost", got)
	}
}

func TestCostCheckWithoutPlan(t *testing.T) {
	c := costChecker(t, costRules, nil, discard)
	_, cost := c.Check("select * from orders", standard)
	if got := costOf(cost, explained("", session.ErrNoPlan)); got != nil {
		t.Errorf("statement Postgres refused got %v; want it left to the session", got)
	}

	_, cost = c.Check("select * from customers", standard)
	if got := costOf(cost, explained("not json", nil)); got == nil || got.Message != "queryguard: statement could not be checked" {
		t.Errorf("unreadable plan got %v; want rejected unchecked", got)
	}
}

func TestCostRulesInWarnMode(t *testing.T) {
	var logs bytes.Buffer
	c := costChecker(t, `{"rules": [{"check": "max_cost", "cost": 10, "mode": "warn"}]}`, nil, logger(&logs))
	_, cost := c.Check("select * from orders", standard)

	if got := costOf(cost, explained(`[{"Plan": {"Node Type": "Seq Scan", "Total Cost": 500}}]`, nil)); got != nil {
		t.Errorf("warn mode rejected with %v", got)
	}
	if !strings.Contains(logs.String(), `msg="would reject statement"`) || !strings.Contains(logs.String(), "rule=max_cost") {
		t.Errorf("log %q; want the would-be rejection", logs.String())
	}
}

func TestNeedsCatalog(t *testing.T) {
	if mustParse(t, `{"rules": [{"check": "max_cost", "cost": 10}]}`).NeedsCatalog() {
		t.Error("max_cost alone needs the catalog")
	}
	if !mustParse(t, costRules).NeedsCatalog() {
		t.Error("max_scan_rows doesn't need the catalog")
	}
}

func TestTenantFromTag(t *testing.T) {
	var logs bytes.Buffer
	p := mustParse(t, `{"trusted_roles": ["app"], "rules": [{"check": "require_where", "match": {"tenants": ["acme"]}}]}`)
	app, bob := p.Checker("app", discard), p.Checker("bob", logger(&logs))

	for c, tc := range map[*Checker]map[string]bool{
		app: {"delete from orders /*tenant='acme'*/": true, "delete from orders /*tenant='other'*/": false, "delete from orders": false},
		// Only a trusted role names its tenant; anyone else's tag is a label.
		bob: {"delete from orders /*tenant='acme'*/": false},
	} {
		for sql, want := range tc {
			if got := rejected(c.Check(sql, standard)); (got != nil) != want {
				t.Errorf("Check(%q) = %v; want blocked = %v", sql, got, want)
			}
		}
	}
	if !strings.Contains(logs.String(), "tenant tag from a role not trusted to name one") {
		t.Errorf("log %q; want the ignored tag", logs.String())
	}
}

func TestRuleMatch(t *testing.T) {
	for _, tc := range []struct {
		match  string
		role   string
		client string
		app    string
		sql    string
		want   bool
	}{
		{`{"roles": ["alice"]}`, "alice", "10.1.2.3", "", "delete from orders", true},
		{`{"roles": ["alice"]}`, "bob", "10.1.2.3", "", "delete from orders", false},
		{`{"application_names": ["batch"]}`, "alice", "10.1.2.3", "batch", "delete from orders", true},
		{`{"application_names": ["batch"]}`, "alice", "10.1.2.3", "web", "delete from orders", false},
		{`{"clients": ["10.0.0.0/8", "192.168.1.7"]}`, "alice", "10.1.2.3", "", "delete from orders", true},
		{`{"clients": ["10.0.0.0/8", "192.168.1.7"]}`, "alice", "192.168.1.7", "", "delete from orders", true},
		{`{"clients": ["10.0.0.0/8"]}`, "alice", "172.16.0.1", "", "delete from orders", false},
		{`{"tags": {"route": "/admin"}}`, "alice", "10.1.2.3", "", "delete from orders /*route='%2Fadmin'*/", true},
		{`{"tags": {"route": "/admin"}}`, "alice", "10.1.2.3", "", "delete from orders /*route='%2Fshop'*/", false},
		// bob isn't trusted to tag statements, so dropping or changing a tag can't take his statements out of a rule.
		{`{"tags": {"route": "/admin"}}`, "bob", "10.1.2.3", "", "delete from orders /*route='%2Fshop'*/", true},
		{`{"tags": {"route": "/admin"}}`, "bob", "10.1.2.3", "", "delete from orders", true},
		{`{"roles": ["alice"], "application_names": ["batch"]}`, "alice", "10.1.2.3", "web", "delete from orders", false},
	} {
		c := mustParse(t, `{"trusted_roles": ["alice"], "rules": [{"check": "require_where", "match": `+tc.match+`}]}`).Checker(tc.role, discard)
		c.Env.Client = netip.MustParseAddr(tc.client)
		set := standard
		set.ApplicationName = tc.app

		if got := rejected(c.Check(tc.sql, set)); (got != nil) != tc.want {
			t.Errorf("match %s for %s from %s (%q): blocked = %v; want %v", tc.match, tc.role, tc.client, tc.app, got != nil, tc.want)
		}
	}
}

func TestGateSpendsBudget(t *testing.T) {
	c := gateChecker(t, `{"tenants": {"alice": {"budget": {"rate": 1, "burst": 150, "when_over": "reject"}}}}`, "alice", discard)

	var got []string
	for range 3 {
		a := pass(t, c, "select * from orders where id = 1", costing(100), false)
		got = append(got, codeOf(a.Reject))
	}

	// 150 units pay for the first; the second runs too, owing 50; the third has nothing left to spend.
	if !slices.Equal(got, []string{"", "", "53000"}) {
		t.Errorf("rejections %q; want only the third, with 53000", got)
	}
}

func TestGateChargesStatementsWithoutPlan(t *testing.T) {
	c := gateChecker(t, `{"tenants": {"alice": {"budget": {"rate": 1, "burst": 15, "min_charge": 10, "when_over": "reject"}}}}`, "alice", discard)
	never := session.Explain{Run: func() (string, error) {
		t.Error("explained a statement EXPLAIN can't plan")
		return "", session.ErrNoPlan
	}}

	var got []string
	for range 3 {
		got = append(got, codeOf(pass(t, c, "begin", never, false).Reject))
	}

	if !slices.Equal(got, []string{"", "", "53000"}) {
		t.Errorf("rejections %q; want the third after two minimum charges", got)
	}
}

func TestGateTakesOneSlotPerBatch(t *testing.T) {
	c := gateChecker(t, `{"scheduler": {"max_active": 1, "queue_timeout": "10ms"}}`, "alice", discard)

	first := pass(t, c, "select 1", costing(1), false)
	// A later statement of the same batch rides on the slot the session holds.
	later := pass(t, c, "select 2", costing(1), true)
	other := pass(t, c, "select 3", costing(1), false)

	if first.Release == nil || later.Release != nil || later.Reject != nil {
		t.Fatalf("first %+v, later %+v; want a slot for the first only", first, later)
	}
	if codeOf(other.Reject) != "53000" {
		t.Errorf("a second session's statement got %v; want 53000 once no slot comes free", other.Reject)
	}
	first.Release()
	if again := pass(t, c, "select 4", costing(1), false); again.Release == nil {
		t.Error("the freed slot was not given out again")
	}
}

func TestGateTimeouts(t *testing.T) {
	config := `{"tenant_defaults": {"statement_timeout": "30s", "idle_in_transaction_timeout": "1m"},
		"tenants": {"batch": {"statement_timeout": "10m"}}}`
	for role, want := range map[string][2]time.Duration{"alice": {30 * time.Second, time.Minute}, "batch": {10 * time.Minute, time.Minute}} {
		a := pass(t, gateChecker(t, config, role, discard), "select 1", costing(1), false)
		if got := [2]time.Duration{a.Timeout, a.IdleInTransaction}; got != want {
			t.Errorf("%s: timeouts %v; want %v", role, got, want)
		}
	}
}

func TestWarnTenantIsNeverHeldBack(t *testing.T) {
	var logs bytes.Buffer
	c := gateChecker(t, `{"scheduler": {"max_active": 1, "queue_timeout": "10ms"},
		"tenants": {"alice": {"mode": "warn", "budget": {"rate": 1, "burst": 1, "when_over": "reject"}}}}`, "alice", logger(&logs))

	for range 3 {
		if a := pass(t, c, "select * from orders where id = 1", costing(100), false); a.Reject != nil {
			t.Fatalf("warn tenant got %v", a.Reject)
		}
	}
	if !strings.Contains(logs.String(), `msg="would reject statement" role=alice rule=budget`) {
		t.Errorf("log %q; want the would-be rejection", logs.String())
	}
}

func TestNoGateWithoutSchedulingOrCostRules(t *testing.T) {
	c := gateChecker(t, `{"rules": [{"check": "require_where"}]}`, "alice", discard)
	if _, gate := c.Check("select 1", standard); gate != nil {
		t.Error("a policy with neither budgets, slots, timeouts nor cost rules gave a gate")
	}
	c = gateChecker(t, `{"tenant_defaults": {"statement_timeout": "1s"}}`, "alice", discard)
	for _, sql := range []string{"begin", "select 1; select 2", "copy orders from stdin"} {
		if _, gate := c.Check(sql, standard); gate == nil {
			t.Errorf("Check(%q) gave no gate; want every statement to pass one", sql)
		}
	}
}

// orderLookup is a lookup through the primary key; orderFullRead is the same statement once that index is gone.
const (
	orderLookup   = `[{"Plan": {"Node Type": "Index Scan", "Schema": "public", "Relation Name": "orders", "Index Name": "orders_pkey", "Total Cost": 8.44}}]`
	orderFullRead = `[{"Plan": {"Node Type": "Seq Scan", "Schema": "public", "Relation Name": "orders", "Total Cost": 241255.31}}]`
	lookupSQL     = "select * from orders where id = 1"
)

// train runs sql n times through c's gate, each run taking took.
func train(t *testing.T, c *Checker, sql string, e session.Explain, n int, took time.Duration) {
	t.Helper()
	for range n {
		a := pass(t, c, sql, e, false)
		if a.Ran == nil {
			t.Fatal("the gate asked for no report of how the statement ran")
		}
		a.Ran(took, true)
		if a.Release != nil {
			a.Release()
		}
	}
}

func TestGateChargesCalibratedCost(t *testing.T) {
	for mode, want := range map[string][]string{"on": {"", "53000"}, "off": {"", ""}} {
		history := &plan.History{}
		trainer := gateChecker(t, `{"scheduler": {"max_active": 100}}`, "alice", discard)
		trainer.Env.History = history
		train(t, trainer, "select 1", costing(100), 10, 10*time.Millisecond)
		train(t, trainer, lookupSQL, costing(100), 10, 100*time.Millisecond)

		// The lookup takes 3.16 times the server's average time per cost unit, so with calibration it costs about 285, not 100.
		c := gateChecker(t, `{"calibration": {"mode": "`+mode+`", "credibility": 1},
			"tenants": {"alice": {"budget": {"rate": 1, "burst": 150, "when_over": "reject"}}}}`, "alice", discard)
		c.Env.History = history
		var got []string
		for range 2 {
			got = append(got, codeOf(pass(t, c, lookupSQL, costing(100), false).Reject))
		}

		if !slices.Equal(got, want) {
			t.Errorf("calibration %s: rejections %q; want %q", mode, got, want)
		}
	}
}

func TestGateSendsPlanFlipToSlowLane(t *testing.T) {
	var logs bytes.Buffer
	c := gateChecker(t, `{"scheduler": {"slow_lane": {"max_active": 1, "queue_timeout": "10ms"}}}`, "alice", logger(&logs))
	train(t, c, lookupSQL, explained(orderLookup, nil), 5, time.Millisecond)
	// The index was dropped, so explaining the statement again gives a full read.
	c.Env.Plans = &plan.Cache{RefreshOneIn: -1}

	first := pass(t, c, lookupSQL, explained(orderFullRead, nil), false)
	second := pass(t, c, lookupSQL, explained(orderFullRead, nil), false)

	// The slow lane has one slot, so the second full read finds it taken.
	if first.Reject != nil || first.Release == nil || codeOf(second.Reject) != "53000" || !strings.Contains(second.Reject.Detail, "slow lane") {
		t.Errorf("first %+v, second %+v; want the first in the slow lane's only slot and the second turned away from it", first, second.Reject)
	}
	if n := strings.Count(logs.String(), `msg="plan flip"`); n != 1 || !strings.Contains(logs.String(), "slow_lane=true") {
		t.Errorf("log %q; want one plan flip, moved to the slow lane", logs.String())
	}
}

func TestPlanFlipInWarnModeOnlyLogs(t *testing.T) {
	var logs bytes.Buffer
	c := gateChecker(t, `{"plan_flips": {"mode": "warn"}, "scheduler": {"slow_lane": {"max_active": 1, "queue_timeout": "10ms"}}}`, "alice", logger(&logs))
	train(t, c, lookupSQL, explained(orderLookup, nil), 5, time.Millisecond)
	c.Env.Plans = &plan.Cache{RefreshOneIn: -1}

	for range 2 {
		if a := pass(t, c, lookupSQL, explained(orderFullRead, nil), false); a.Reject != nil {
			t.Fatalf("got %v; want the full read to run in the fast lane", a.Reject)
		}
	}
	if !strings.Contains(logs.String(), `msg="plan flip"`) || !strings.Contains(logs.String(), "slow_lane=false") {
		t.Errorf("log %q; want the flip logged, not acted on", logs.String())
	}
}

func TestPlanFlipWithoutSchedulerOnlyLogs(t *testing.T) {
	var logs bytes.Buffer
	c := costChecker(t, `{"rules": [{"check": "max_cost", "cost": 1000000}]}`, nil, logger(&logs))
	train(t, c, lookupSQL, explained(orderLookup, nil), 5, time.Millisecond)
	c.Env.Plans = &plan.Cache{RefreshOneIn: -1}

	pass(t, c, lookupSQL, explained(orderFullRead, nil), false)

	if !strings.Contains(logs.String(), `msg="plan flip"`) || !strings.Contains(logs.String(), "slow_lane=false") {
		t.Errorf("log %q; want the flip logged with no slow lane to send it to", logs.String())
	}
}

func TestPlanFlipLogNamesStaleTables(t *testing.T) {
	var logs bytes.Buffer
	c := gateChecker(t, `{"scheduler": {"max_active": 100}}`, "alice", logger(&logs))
	c.Env.Tables = staleTables{"public.orders"}
	train(t, c, lookupSQL, explained(orderLookup, nil), 5, time.Millisecond)
	c.Env.Plans = &plan.Cache{RefreshOneIn: -1}

	pass(t, c, lookupSQL, explained(orderFullRead, nil), false)

	if !strings.Contains(logs.String(), "stale_tables=[public.orders]") {
		t.Errorf("log %q; want the stale table named", logs.String())
	}
}

func TestSlowRunExplainsStatementAgain(t *testing.T) {
	var logs bytes.Buffer
	c := gateChecker(t, `{"scheduler": {"slow_lane": {"max_active": 1, "queue_timeout": "10ms"}}}`, "alice", logger(&logs))
	explains := 0
	lookup := session.Explain{Run: func() (string, error) { explains++; return orderLookup, nil }}
	train(t, c, lookupSQL, lookup, 5, time.Millisecond)

	// Postgres ran a generic plan, or the index went away outside the proxy, so the cached plan no longer says how it runs.
	a := pass(t, c, lookupSQL, lookup, false)
	a.Ran(3*time.Second, true)
	a.Release()
	next := pass(t, c, lookupSQL, lookup, false)
	taken := pass(t, c, lookupSQL, lookup, false)

	if explains != 2 {
		t.Errorf("%d explains; want the cached plan explained again after the slow run", explains)
	}
	if next.Release == nil || codeOf(taken.Reject) != "53000" || !strings.Contains(logs.String(), "far slower") {
		t.Errorf("next %+v, then %v, log %q; want the statement held in the slow lane after its slow run", next, taken.Reject, logs.String())
	}
}

func TestGenericStandInIsNotLearned(t *testing.T) {
	c := gateChecker(t, `{"scheduler": {"max_active": 100}}`, "alice", discard)
	e := explained(orderLookup, nil)
	e.Generic = true

	if a := pass(t, c, lookupSQL, e, false); a.Ran != nil {
		t.Error("a generic plan, explained because the values were too large, was recorded as the statement's plan")
	}
}

func TestCursorIsNotLearned(t *testing.T) {
	c := gateChecker(t, `{"scheduler": {"max_active": 100}}`, "alice", discard)

	// Opening a cursor runs nothing; the work happens in FETCH, which isn't timed.
	if a := pass(t, c, "declare c cursor for "+lookupSQL, explained(orderLookup, nil), false); a.Ran != nil {
		t.Error("DECLARE's run was to be recorded as its plan's timing")
	}
}

func TestSchemaChangeForgetsCachedPlans(t *testing.T) {
	c := costChecker(t, `{"rules": [{"check": "max_cost", "cost": 1000000}]}`, nil, discard)
	explains := 0
	lookup := session.Explain{Run: func() (string, error) { explains++; return orderLookup, nil }}
	for _, sql := range []string{lookupSQL, lookupSQL, "drop index orders_pkey", lookupSQL, "analyze orders", lookupSQL} {
		_, gate := c.Check(sql, standard)
		if gate == nil {
			t.Fatalf("Check(%q) gave no gate", sql)
		}
		// Plans are forgotten once the change is committed, as another session's EXPLAIN may run before that.
		if a := gate(t.Context(), lookup, false); a.Settled != nil {
			a.Settled()
		}
	}

	if explains != 3 {
		t.Errorf("%d explains; want the lookup explained again after DROP INDEX and after ANALYZE", explains)
	}
}

func TestHolderAppliesReloadToExistingCheckers(t *testing.T) {
	var h Holder
	h.Store(mustParse(t, `{}`))
	c := h.Checker("alice", discard)
	if got := rejected(c.Check("delete from orders", standard)); got != nil {
		t.Fatalf("got %v before the reload", got)
	}

	h.Store(mustParse(t, `{"rules": [{"check": "require_where"}]}`))

	if got := rejected(c.Check("delete from orders", standard)); got == nil {
		t.Error("an open session kept the old rules after the reload")
	}
}

func TestSchedConfigWithoutAdaptive(t *testing.T) {
	if c := mustParse(t, `{"scheduler": {"max_active": 8}}`).SchedConfig().Controller; c != nil {
		t.Errorf("Controller = %v; want none without adaptive", c)
	}
}

func TestGateGivesSlotsByPriority(t *testing.T) {
	config := `{"trusted_roles": ["app"], "scheduler": {"max_active": 1, "queue_timeout": "1m"},
		"tenants": {"batch": {"priority": "best_effort"}, "ops": {"priority": "critical"}}}`
	// The second statement arrives later, so it goes first only with a higher priority.
	for name, tc := range map[string]struct {
		first, second statementBy
		secondFirst   bool
	}{
		"tenant setting":                                {statementBy{"batch", "select 1"}, statementBy{"alice", "select 1"}, true},
		"critical tenant":                               {statementBy{"alice", "select 1"}, statementBy{"ops", "select 1"}, true},
		"tag from a trusted role":                       {statementBy{"app", "select 1"}, statementBy{"app", "select 1 /*priority='critical'*/"}, true},
		"lowering tag from an untrusted role":           {statementBy{"alice", "select 1 /*priority='best_effort'*/"}, statementBy{"bob", "select 1"}, true},
		"raising tag from an untrusted role is ignored": {statementBy{"alice", "select 1"}, statementBy{"bob", "select 1 /*priority='critical'*/"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := mustParse(t, config)
				s := sched.New(p.SchedConfig())
				checker := func(role string) *Checker {
					c := p.Checker(role, discard)
					c.Env = Env{Database: "shop", Plans: &plan.Cache{RefreshOneIn: -1}, Scheduler: s}
					return c
				}
				hold := pass(t, checker("x"), "select 0", costing(1), false)

				var mu sync.Mutex
				var order []string
				var wg sync.WaitGroup
				for _, st := range []statementBy{tc.first, tc.second} {
					wg.Go(func() {
						a := pass(t, checker(st.role), st.sql, costing(1), false)
						mu.Lock()
						order = append(order, st.role+": "+st.sql)
						mu.Unlock()
						if a.Release != nil {
							a.Release()
						}
					})
					synctest.Wait()
				}
				hold.Release()
				wg.Wait()

				want := tc.first
				if tc.secondFirst {
					want = tc.second
				}
				if order[0] != want.role+": "+want.sql {
					t.Errorf("first slot went to %q; want %q", order[0], want.role+": "+want.sql)
				}
			})
		})
	}
}

// statementBy is a statement sent by a role.
type statementBy struct{ role, sql string }

func TestShedStatementIsRejectedAsBusy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := mustParse(t, `{"scheduler": {"max_active": 2, "queue_timeout": "1m"}, "tenants": {"batch": {"priority": "best_effort"}}}`)
		limit := &lowered{}
		cfg := p.SchedConfig()
		cfg.Controller = limit
		s := sched.New(cfg)
		go s.Run(t.Context())
		c := p.Checker("batch", discard)
		c.Env = Env{Database: "shop", Plans: &plan.Cache{RefreshOneIn: -1}, Scheduler: s}
		pass(t, c, "select 1", costing(1), false)
		limit.on.Store(true)
		time.Sleep(sched.AdjustInterval)
		synctest.Wait()

		a := pass(t, c, "select 1", costing(1), false)

		if codeOf(a.Reject) != "53000" || !strings.Contains(a.Reject.Message, "overloaded") {
			t.Errorf("best-effort statement under overload got %v; want 53000 saying the server is overloaded", a.Reject)
		}
	})
}

// lowered is a Controller that drops the limit to 1 once on is set.
type lowered struct{ on atomic.Bool }

func (l *lowered) Adjust(limit int, _ sched.Signal) int {
	if l.on.Load() {
		return 1
	}
	return limit
}

func TestGateReportsSlowdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := mustParse(t, `{"scheduler": {"max_active": 4}}`)
		seen := &signals{}
		cfg := p.SchedConfig()
		cfg.Controller = seen
		s := sched.New(cfg)
		go s.Run(t.Context())
		c := p.Checker("alice", discard)
		c.Env = Env{Database: "shop", Plans: &plan.Cache{RefreshOneIn: -1}, Scheduler: s}
		train(t, c, lookupSQL, explained(orderLookup, nil), 5, 10*time.Millisecond)
		time.Sleep(sched.AdjustInterval)
		synctest.Wait()

		train(t, c, lookupSQL, explained(orderLookup, nil), 1, 40*time.Millisecond)
		time.Sleep(sched.AdjustInterval)
		synctest.Wait()

		// The first five runs set the plan's usual time, so they report nothing; the sixth took four times as long.
		got := seen.last()
		if got[0].Slowdown != 0 || math.Abs(got[1].Slowdown-4) > 1e-3 {
			t.Errorf("slowdowns %v, %v; want 0 while learning, then 4", got[0].Slowdown, got[1].Slowdown)
		}
	})
}

// signals is a Controller that keeps the limit and records each Signal.
type signals struct {
	mu   sync.Mutex
	seen []sched.Signal
}

func (s *signals) Adjust(limit int, sig sched.Signal) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, sig)
	return limit
}

// last returns the last two signals.
func (s *signals) last() [2]sched.Signal {
	s.mu.Lock()
	defer s.mu.Unlock()
	return [2]sched.Signal(s.seen[len(s.seen)-2:])
}

func TestSchedConfig(t *testing.T) {
	p := mustParse(t, `{"scheduler": {"max_active": 8, "queue_timeout": "2s", "slow_lane": {"max_active": 1, "queue_timeout": "30s"},
			"adaptive": {"floor": 2, "backoff": 0.5, "max_slowdown": 3, "lock_wait_share": 0.1}},
		"tenant_defaults": {"budget": {"rate": 10}},
		"tenants": {"acme": {"budget": {"rate": 100, "burst": 1000, "share": 2, "min_charge": 5, "when_over": "slow"}}, "bob": {"mode": "warn"}}}`)

	got := p.SchedConfig()

	want := sched.Config{
		Fast:       sched.Lane{MaxActive: 8, QueueTimeout: 2 * time.Second},
		Slow:       sched.Lane{MaxActive: 1, QueueTimeout: 30 * time.Second},
		Budgets:    map[string]sched.Budget{"acme": {Rate: 100, Burst: 1000, Share: 2, MinCharge: 5, WhenOver: sched.SlowLane}},
		Default:    sched.Budget{Rate: 10},
		Controller: sched.AIMD{Floor: 2, Backoff: 0.5, MaxSlowdown: 3, LockWaitShare: 0.1},
	}
	if got.Fast != want.Fast || got.Slow != want.Slow || got.Default != want.Default || !maps.Equal(got.Budgets, want.Budgets) ||
		got.Controller != want.Controller {
		t.Errorf("SchedConfig = %+v; want %+v", got, want)
	}
}

func TestConnectionLimits(t *testing.T) {
	p := mustParse(t, `{"max_connections": 100, "tenant_max_connections": 10, "tenants": {"batch": {"max_connections": 2}}}`)

	for role, want := range map[string]int{"alice": 10, "batch": 2} {
		total, tenant := p.ConnectionLimits(role)
		if total != 100 || tenant != want {
			t.Errorf("ConnectionLimits(%s) = %d, %d; want 100, %d", role, total, tenant, want)
		}
	}
}

func TestParseRejectsBadConfig(t *testing.T) {
	for config, want := range map[string]string{
		`{"rules": [{"check": "no_such_check"}]}`:                             "no_such_check",
		`{"rules": [{"check": "require_where", "mode": "loud"}]}`:             "loud",
		`{"rules": [{"check": "require_where"}, {"check": "require_where"}]}`: "twice",
		`{"rules": [{"check": "schema_allowlist"}]}`:                          "schemas",
		`{"rules": [{"check": "require_where", "schemas": ["public"]}]}`:      "schemas",
		`{"unchecked": "maybe"}`:                                              "maybe",
		`{"tenants": {"alice": {"mode": "loud"}}}`:                            "loud",
		`{"max_connections": -1}`:                                             "max_connections",
		`{"tenants": {"alice": {"max_connections": -1}}}`:                     "max_connections",
		`{"rule": []}`:                                                               "rule",
		`{"rules": [{"check": "max_cost"}]}`:                                         "cost",
		`{"rules": [{"check": "max_cost", "cost": -1}]}`:                             "cost",
		`{"rules": [{"check": "max_scan_rows"}]}`:                                    "rows",
		`{"rules": [{"check": "require_where", "cost": 5}]}`:                         "cost",
		`{"rules": [{"check": "max_cost", "cost": 5, "rows": 5}]}`:                   "rows",
		`{"tenants": {"a": {"budget": {"rate": -1}}}}`:                               "rate",
		`{"tenants": {"a": {"budget": {"rate": 10, "when_over": "later"}}}}`:         "later",
		`{"tenants": {"a": {"budget": {"burst": 10}}}}`:                              "burst",
		`{"tenant_defaults": {"statement_timeout": "soon"}}`:                         "soon",
		`{"tenant_defaults": {"statement_timeout": "-1s"}}`:                          "statement_timeout",
		`{"tenant_defaults": {"mode": "warn"}}`:                                      "tenant_defaults",
		`{"scheduler": {"max_active": -1}}`:                                          "max_active",
		`{"rules": [{"check": "deny_ddl", "match": {"clients": ["10.0.0.0/33"]}}]}`:  "10.0.0.0/33",
		`{"calibration": {"mode": "maybe"}}`:                                         "maybe",
		`{"calibration": {"credibility": -1}}`:                                       "credibility",
		`{"plan_flips": {"mode": "loud"}}`:                                           "loud",
		`{"plan_flips": {"quarantine": "-1m"}}`:                                      "quarantine",
		`{"rules": [{"check": "deny_ddl", "match": {"tags": {"route": "/admin"}}}]}`: "trusted_roles",
		`{"scheduler": {"adaptive": {}}}`:                                            "max_active",
		`{"scheduler": {"max_active": 4, "adaptive": {"floor": 8}}}`:                 "floor",
		`{"scheduler": {"max_active": 4, "adaptive": {"backoff": 1}}}`:               "backoff",
		`{"scheduler": {"max_active": 4, "adaptive": {"max_slowdown": 0.5}}}`:        "max_slowdown",
		`{"scheduler": {"max_active": 4, "adaptive": {"lock_wait_share": -1}}}`:      "lock_wait_share",
		`{"tenants": {"a": {"priority": "urgent"}}}`:                                 "urgent",
	} {
		if _, err := Parse([]byte(config)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%s) = %v; want an error mentioning %q", config, err, want)
		}
	}
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queryguard.json")
	if err := os.WriteFile(path, []byte(allRules), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if rejected(p.Checker("alice", discard).Check("delete from orders", standard)) == nil {
		t.Error("loaded policy allowed DELETE without WHERE")
	}
}

var discard = slog.New(slog.DiscardHandler)

// rejected returns Check's error, dropping its cost check.
func rejected(e *pgproto3.ErrorResponse, _ session.Gate) *pgproto3.ErrorResponse { return e }

// gateChecker checks role's statements under config with a scheduler of its own.
func gateChecker(t *testing.T, config, role string, log *slog.Logger) *Checker {
	t.Helper()
	p := mustParse(t, config)
	c := p.Checker(role, log)
	c.Env = Env{Database: "shop", Plans: &plan.Cache{RefreshOneIn: -1}, Scheduler: sched.New(p.SchedConfig())}
	return c
}

// pass checks sql and passes its gate with explain, failing the test when there is no gate.
func pass(t *testing.T, c *Checker, sql string, explain session.Explain, running bool) session.Admission {
	t.Helper()
	rej, gate := c.Check(sql, standard)
	if rej != nil || gate == nil {
		t.Fatalf("Check(%q) = %v and gate %v; want a gate", sql, rej, gate != nil)
	}
	return gate(t.Context(), explain, running)
}

// gateOf checks sql and returns its gate, failing the test when it is rejected or has none.
func gateOf(t *testing.T, c *Checker, sql string) session.Gate {
	t.Helper()
	rej, gate := c.Check(sql, standard)
	if rej != nil || gate == nil {
		t.Fatalf("Check(%q) = %v and gate %v; want a gate", sql, rej, gate != nil)
	}
	return gate
}

// costing explains any statement as an index scan of the given cost.
func costing(cost float64) session.Explain {
	return explained(fmt.Sprintf(`[{"Plan": {"Node Type": "Index Scan", "Total Cost": %g}}]`, cost), nil)
}

func codeOf(e *pgproto3.ErrorResponse) string {
	if e == nil {
		return ""
	}
	return e.Code
}

// costOf passes g as the first statement of a batch and returns its rejection, or nil.
func costOf(g session.Gate, e session.Explain) *pgproto3.ErrorResponse {
	return g(context.Background(), e, false).Reject
}

// costChecker checks alice's statements in database shop with a fresh plan cache and the given table sizes.
func costChecker(t *testing.T, config string, sizes tables, log *slog.Logger) *Checker {
	t.Helper()
	c := mustParse(t, config).Checker("alice", log)
	c.Env = Env{Database: "shop", Plans: &plan.Cache{RefreshOneIn: -1}, Tables: sizes}
	return c
}

// explained is an Explain whose Run returns out and err.
func explained(out string, err error) session.Explain {
	return session.Explain{Run: func() (string, error) { return out, err }}
}

// tables are table sizes keyed by schema.name.
type tables map[string]float64

func (ts tables) Rows(_ string, t plan.Table) (float64, bool) {
	n, ok := ts[t.String()]
	return n, ok
}

func (ts tables) Stale(string, plan.Table) bool { return false }

// staleTables have no known size, and the listed ones have stale statistics.
type staleTables []string

func (ts staleTables) Rows(string, plan.Table) (float64, bool) { return 0, false }
func (ts staleTables) Stale(_ string, t plan.Table) bool       { return slices.Contains(ts, t.String()) }

// standard is how Postgres reads SQL by default, which is how the parser reads it.
var standard = session.Settings{StandardConformingStrings: "on", ClientEncoding: "UTF8"}

func logger(buf *bytes.Buffer) *slog.Logger { return slog.New(slog.NewTextHandler(buf, nil)) }

func mustParse(t *testing.T, config string) *Policy {
	t.Helper()
	p, err := Parse([]byte(config))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// ruleOf returns the rule named in a rejection's message, or "" when the statement was allowed.
func ruleOf(e *pgproto3.ErrorResponse) string {
	if e == nil {
		return ""
	}
	for name := range checks {
		if strings.Contains(e.Message, " "+name+" ") {
			return name
		}
	}
	return "unknown: " + e.Message
}
