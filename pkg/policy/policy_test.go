package policy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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

func TestSessionThatChangesItsRoleExplainsEveryStatement(t *testing.T) {
	for _, set := range []string{"set role reporting", "select set_config('role', 'reporting', true)"} {
		c := costChecker(t, costRules, nil, discard)
		const sql = "select * from orders where id = 1"
		if got := costOf(gateOf(t, c, sql), costing(8)); got != nil {
			t.Fatalf("cheap statement got %v", got)
		}

		c.Check(set, standard)

		// Row-level security can give the new role another plan for the same text.
		if got := costOf(gateOf(t, c, sql), costing(5000)); ruleOf(got) != "max_cost" {
			t.Errorf("after %q, costly plan got %v; want max_cost, not the plan cached for the login role", set, got)
		}
	}
}

func TestRoleChangedUnderAPolicyThatParsesNothingIsRemembered(t *testing.T) {
	current := mustParse(t, `{}`)
	c := newChecker(func() *Policy { return current }, "alice", discard)
	c.Env = Env{Database: "shop", Plans: &plan.Cache{RefreshOneIn: -1}}
	const sql = "select * from orders where id = 1"

	c.Check("SET ROLE reporting", standard)
	// A reload brings in cost rules after the role changed.
	current = mustParse(t, costRules)
	costOf(gateOf(t, c, sql), costing(8))

	if got := costOf(gateOf(t, c, sql), costing(5000)); ruleOf(got) != "max_cost" {
		t.Errorf("costly plan got %v; want max_cost, not a cached plan", got)
	}
}

func TestPlansCachedAfterARoleChangeStayOutOfOtherSessions(t *testing.T) {
	c := costChecker(t, costRules, nil, discard)
	other := costChecker(t, costRules, nil, discard)
	other.Env.Plans = c.Env.Plans
	const sql = "select * from orders where id = 1"

	c.Check("set role reporting", standard)
	costOf(gateOf(t, c, sql), costing(8))

	if got := costOf(gateOf(t, other, sql), costing(5000)); ruleOf(got) != "max_cost" {
		t.Errorf("another session got %v; want its own plan, not one made under the changed role", got)
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
		got = append(got, codeOf(pass(t, c, "show work_mem", never, false).Reject))
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

func TestGateGivesTheTenantsTransactionTimeout(t *testing.T) {
	config := `{"tenant_defaults": {"transaction_timeout": "5m"}, "tenants": {"batch": {"transaction_timeout": "1h"}}}`
	for role, want := range map[string]time.Duration{"alice": 5 * time.Minute, "batch": time.Hour} {
		// BEGIN needs no slot or budget, but it opens the transaction the limit is for.
		for _, sql := range []string{"begin", "select 1"} {
			if a := pass(t, gateChecker(t, config, role, discard), sql, costing(1), false); a.TransactionTimeout != want {
				t.Errorf("%s, %s: transaction timeout %v; want %v", role, sql, a.TransactionTimeout, want)
			}
		}
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

func TestGateTellsTheBackendWhatRuns(t *testing.T) {
	for _, tc := range []struct {
		config, sql string
		want        []running
	}{
		// DDL is reported even with nothing to schedule, for the DDL guard.
		{`{}`, "alter table orders add column note text", []running{{"alice", true}, {"alice", false}}},
		{`{"scheduler": {"max_active": 4}}`, "select 1", []running{{"alice", false}, {"alice", false}}},
	} {
		c := mustParse(t, tc.config).Checker("alice", discard)
		b := &backend{}
		c.Env = Env{Database: "shop", Plans: &plan.Cache{RefreshOneIn: -1}, Scheduler: sched.New(mustParse(t, tc.config).SchedConfig()), Backend: b}

		a := pass(t, c, tc.sql, costing(1), false)
		if a.Ran == nil {
			t.Fatalf("%s: no Ran to report the statement's end", tc.sql)
		}
		a.Ran(time.Millisecond, true)

		if !slices.Equal(b.runs, tc.want) {
			t.Errorf("%s: backend told %v; want %v", tc.sql, b.runs, tc.want)
		}
	}
}

func TestGateTellsTheBackendWhenTheServerIsIdle(t *testing.T) {
	c := mustParse(t, `{}`).Checker("alice", discard)
	b := &backend{}
	c.Env = Env{Database: "shop", Plans: &plan.Cache{RefreshOneIn: -1}, Backend: b}

	// A Bind with no Execute passes the gate, but the server never runs it, so only the server going idle ends it.
	a := pass(t, c, "alter table orders add column note text", costing(1), false)
	if a.Idle == nil {
		t.Fatal("no Idle to report the server idle")
	}
	a.Idle()

	if want := []running{{"alice", true}, {"alice", false}}; !slices.Equal(b.runs, want) {
		t.Errorf("backend told %v; want %v", b.runs, want)
	}
}

func TestDDLGetsAGateOnlyForTheGuard(t *testing.T) {
	for config, wantGate := range map[string]bool{`{"ddl_guard": {"mode": "off"}}`: false, `{}`: true} {
		c := mustParse(t, config).Checker("alice", discard)
		c.Env.Backend = &backend{}
		if _, gate := c.Check("alter table orders add column note text", standard); (gate != nil) != wantGate {
			t.Errorf("%s: DDL got a gate: %v; want %v", config, gate != nil, wantGate)
		}
		// Without a Backend no one needs to know, so nothing is parsed.
		c.Env.Backend = nil
		if _, gate := c.Check("alter table orders add column note text", standard); gate != nil {
			t.Errorf("%s: DDL got a gate with no Backend to tell", config)
		}
	}
}

func TestDDLGuard(t *testing.T) {
	for config, want := range map[string]DDLGuard{
		`{}`: {Mode: Enforce, LockTimeout: Duration(DefaultDDLLockTimeout)},
		`{"ddl_guard": {"mode": "warn", "lock_timeout": "5s"}}`: {Mode: Warn, LockTimeout: Duration(5 * time.Second)},
		`{"ddl_guard": {"mode": "off"}}`:                        {Mode: "off", LockTimeout: Duration(DefaultDDLLockTimeout)},
	} {
		if got := mustParse(t, config).DDLGuard(); got != want {
			t.Errorf("%s: DDLGuard() = %+v; want %+v", config, got, want)
		}
	}
}

func TestServerSignals(t *testing.T) {
	p := mustParse(t, `{"replication_lag": {"max": "10s"}, "mvcc_horizon": {"max_age": "1m", "watch": ["public.jobs"], "max_dead_tuples": 5000}}`)
	if got := p.ReplicationLag(); got != 10*time.Second {
		t.Errorf("ReplicationLag() = %v; want 10s", got)
	}
	want := Horizon{MaxAge: Duration(time.Minute), Watch: []string{"public.jobs"}, MaxDeadTuples: 5000}
	if got := p.Horizon(); got.MaxAge != want.MaxAge || got.MaxDeadTuples != want.MaxDeadTuples || !slices.Equal(got.Watch, want.Watch) {
		t.Errorf("Horizon() = %+v; want %+v", got, want)
	}
	if got := p.Watched(); !slices.Equal(got, []plan.Table{{Schema: "public", Name: "jobs"}}) {
		t.Errorf("Watched() = %v; want public.jobs", got)
	}
	if empty := mustParse(t, `{}`); empty.ReplicationLag() != 0 || empty.Horizon().MaxAge != 0 || empty.Watched() != nil {
		t.Error("an empty config watches replication lag or the MVCC horizon")
	}
}

func TestHeldStatementIsRejectedAsHeldBack(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := gateChecker(t, `{"scheduler": {"max_active": 2, "queue_timeout": "1s"}, "tenants": {"batch": {"priority": "best_effort"}}}`, "batch", discard)
		c.Env.Scheduler.HoldBestEffort(true)

		a := pass(t, c, "select 1", costing(1), false)

		if codeOf(a.Reject) != "53000" || !strings.Contains(a.Reject.Message, "held back") {
			t.Errorf("held best-effort statement got %v; want 53000 saying it was held back", a.Reject)
		}
	})
}

func TestGateTruesUpToMeasuredTime(t *testing.T) {
	history := &plan.History{}
	trainer := gateChecker(t, `{"scheduler": {"max_active": 100}}`, "alice", discard)
	trainer.Env.History = history
	// 100 cost units take 10ms here, so a second is worth 10000.
	train(t, trainer, "select 1", costing(100), 10, 10*time.Millisecond)
	c := gateChecker(t, `{"tenants": {"alice": {"budget": {"rate": 1, "burst": 1000, "when_over": "reject"}}}}`, "alice", discard)
	c.Env.History = history

	// The plan said 100, which the budget pays easily, but the statement ran for a second.
	a := pass(t, c, lookupSQL, costing(100), false)
	a.Ran(time.Second, true)

	if next := pass(t, c, lookupSQL, costing(100), false); codeOf(next.Reject) != "53000" {
		t.Errorf("next statement got %v; want 53000 once the first was charged for its second", next.Reject)
	}
}

func TestOverloadQueue(t *testing.T) {
	for config, want := range map[string][2]time.Duration{
		`{}`: {DefaultStandingAfter, DefaultStandingTimeout},
		`{"scheduler": {"overload_queue": {"standing_after": "2s", "timeout": "1s"}}}`: {2 * time.Second, time.Second},
		`{"scheduler": {"overload_queue": {"mode": "off"}}}`:                           {0, 0},
	} {
		cfg := mustParse(t, config).SchedConfig()
		if got := [2]time.Duration{cfg.Fast.StandingAfter, cfg.Fast.StandingTimeout}; got != want {
			t.Errorf("%s: fast lane stands after %v and drops after %v; want %v", config, got[0], got[1], want)
		}
		// The slow lane is for statements that may wait long.
		if cfg.Slow.StandingAfter != 0 {
			t.Errorf("%s: the slow lane can stand", config)
		}
	}
}

func TestStatementPastItsDeadlineIsAnsweredAtOnce(t *testing.T) {
	for name, tc := range map[string]struct {
		startup map[string]string
		sql     string
		usual   time.Duration // how long the statement usually runs, 0 for unknown
		lane    bool          // the only slot is taken
		want    time.Duration // when the gate gives up; 0 is at once
	}{
		"deadline tag":                           {nil, lookupSQL + " /*deadline='200ms'*/", 0, true, 200 * time.Millisecond},
		"statement_timeout at login":             {map[string]string{"statement_timeout": "300"}, lookupSQL, 0, true, 300 * time.Millisecond},
		"the earlier of the two":                 {map[string]string{"statement_timeout": "1min"}, lookupSQL + " /*deadline='0.5s'*/", 0, true, 500 * time.Millisecond},
		"waits only as long as it can still end": {nil, lookupSQL + " /*deadline='150ms'*/", 100 * time.Millisecond, true, 50 * time.Millisecond},
		"would not end in time even unqueued":    {nil, lookupSQL + " /*deadline='500ms'*/", time.Second, false, 0},
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := gateChecker(t, `{"scheduler": {"max_active": 1, "queue_timeout": "1m"}}`, "alice", discard)
				if tc.usual > 0 {
					train(t, c, lookupSQL, explained(orderLookup, nil), 5, tc.usual)
				}
				if tc.lane {
					pass(t, c, "select 0", costing(1), false)
				}
				if rej := c.CheckStartup(maps.All(tc.startup)); rej != nil {
					t.Fatal(rej)
				}

				start := time.Now()
				a := pass(t, c, tc.sql, explained(orderLookup, nil), false)

				// A usual time learned from runs can be off by a nanosecond.
				if took := time.Since(start); codeOf(a.Reject) != "57014" || !strings.Contains(a.Reject.Message, "deadline") || (took-tc.want).Abs() > time.Microsecond {
					t.Errorf("got %v after %v; want 57014 about the deadline after %v", a.Reject, time.Since(start), tc.want)
				}
			})
		})
	}
}

func TestStatementWithinItsDeadlineRuns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := gateChecker(t, `{"scheduler": {"max_active": 1, "queue_timeout": "1m"}}`, "alice", discard)
		hold := pass(t, c, "select 0", costing(1), false)
		time.AfterFunc(100*time.Millisecond, hold.Release)

		if a := pass(t, c, lookupSQL+" /*deadline='1s'*/", explained(orderLookup, nil), false); a.Reject != nil {
			t.Errorf("statement whose slot came free in time got %v", a.Reject)
		}
	})
}

func TestPreparedStatementsDeadlineCountsFromEachExecution(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := gateChecker(t, `{"scheduler": {"max_active": 1}}`, "alice", discard)
		if rej := c.CheckStartup(maps.All(map[string]string{"statement_timeout": "1s"})); rej != nil {
			t.Fatal(rej)
		}
		gate := gateOf(t, c, lookupSQL)

		// A prepared statement is checked once, at Parse, and its gate is passed at every Bind.
		time.Sleep(time.Minute)
		if a := gate(t.Context(), explained(orderLookup, nil), false); a.Reject != nil {
			t.Errorf("statement bound a minute after it was prepared got %v", a.Reject)
		}
	})
}

func TestDeadlineForgetsTheLoginTimeoutOnceTheSessionSetsItsOwn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := gateChecker(t, `{"scheduler": {"max_active": 1, "queue_timeout": "1m"}}`, "alice", discard)
		if rej := c.CheckStartup(maps.All(map[string]string{"statement_timeout": "300"})); rej != nil {
			t.Fatal(rej)
		}
		pass(t, c, "set statement_timeout = 0", costing(1), false).Release()
		hold := pass(t, c, "select 0", costing(1), false)
		time.AfterFunc(400*time.Millisecond, hold.Release)

		// QueryGuard can't tell what the session set it to, so it no longer guesses when the client gives up.
		if a := pass(t, c, lookupSQL, explained(orderLookup, nil), false); a.Reject != nil {
			t.Errorf("statement after SET statement_timeout got %v; want it run once the slot came free", a.Reject)
		}
	})
}

func TestTransactionControlNeedsNoSlotOrBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := gateChecker(t, `{"scheduler": {"max_active": 1, "queue_timeout": "1m"},
			"tenants": {"alice": {"budget": {"rate": 1, "burst": 1, "when_over": "reject"}}}}`, "alice", discard)
		pass(t, c, "select 0", costing(5), false)

		// The slot may be held by a statement waiting on this transaction's locks, which only its COMMIT or ROLLBACK frees.
		for _, sql := range []string{"commit", "rollback", "begin"} {
			start := time.Now()
			if a := pass(t, c, sql, session.Explain{}, false); a.Reject != nil || a.Release != nil || time.Since(start) != 0 {
				t.Errorf("%s got %v and a slot %v after %v; want it run at once without one", sql, a.Reject, a.Release != nil, time.Since(start))
			}
		}
	})
}

func TestBudgetWaitPastTheDeadlineIsAnsweredAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := gateChecker(t, `{"tenants": {"alice": {"budget": {"rate": 100, "burst": 100}}}}`, "alice", discard)
		c.Env.Scheduler.Charge("alice", 300)

		start := time.Now()
		a := pass(t, c, lookupSQL+" /*deadline='1s'*/", costing(1), false)

		// The budget refills in 2s, after the deadline, so there is no point waiting.
		if codeOf(a.Reject) != "57014" || time.Since(start) != 0 {
			t.Errorf("got %v after %v; want 57014 at once", a.Reject, time.Since(start))
		}
	})
}

func TestTenantMode(t *testing.T) {
	p := mustParse(t, `{"tenants": {"bob": {"mode": "warn"}}}`)
	if p.TenantMode("bob") != Warn || p.TenantMode("alice") != Enforce {
		t.Errorf("modes %q and %q; want warn for bob and enforce for alice", p.TenantMode("bob"), p.TenantMode("alice"))
	}
}

// backend records what a Checker says its session runs.
type backend struct {
	runs     []running
	blocking chan struct{} // closed when others wait on the session's locks; nil never is
}

type running struct {
	tenant string
	ddl    bool
}

func (b *backend) Running(tenant string, ddl bool) { b.runs = append(b.runs, running{tenant, ddl}) }
func (b *backend) Blocking() <-chan struct{}       { return b.blocking }

func TestServerWideRulesGateEveryStatement(t *testing.T) {
	for _, config := range []string{
		`{"replication_lag": {"max": "1s"}, "tenants": {"alice": {"priority": "best_effort"}}}`,
		`{"mvcc_horizon": {"max_age": "1m"}, "tenants": {"alice": {"priority": "best_effort"}}}`,
	} {
		synctest.Test(t, func(t *testing.T) {
			c := gateChecker(t, config, "alice", discard)
			b := &backend{}
			c.Env.Backend = b
			c.Env.Scheduler.HoldBestEffort(true)

			// Holds and caps work at the slot a statement takes, and the horizon check finds a snapshot's tenant from what runs.
			rej, gate := c.Check("select 1", standard)
			if rej != nil || gate == nil {
				t.Fatalf("%s: Check gave %v and gate %v; want a gate", config, rej, gate != nil)
			}
			if a := gate(t.Context(), session.Explain{}, false); codeOf(a.Reject) != "53000" || len(b.runs) != 0 {
				t.Errorf("%s: held statement got %v and ran %v; want 53000 and nothing run", config, a.Reject, b.runs)
			}
			c.Env.Scheduler.HoldBestEffort(false)
			if a := gate(t.Context(), session.Explain{}, false); a.Reject != nil || !slices.Equal(b.runs, []running{{"alice", false}}) {
				t.Errorf("%s: got %v and ran %v; want alice's statement run", config, a.Reject, b.runs)
			}
		})
	}
}

func TestSessionHoldingLocksOthersWaitOnSkipsTheQueue(t *testing.T) {
	for name, config := range map[string]string{
		"no slot free": `{"scheduler": {"max_active": 1, "queue_timeout": "1m"}}`,
		"budget spent": `{"tenants": {"alice": {"budget": {"rate": 1, "burst": 1, "when_over": "queue"}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := gateChecker(t, config, "alice", discard)
				b := &backend{blocking: make(chan struct{})}
				c.Env.Backend = b
				// The only slot, or the whole budget, goes to a statement that will wait on this session's locks.
				pass(t, c, "select 0", costing(5), false)
				time.AfterFunc(time.Second, func() { close(b.blocking) })

				// Only this session's next statement, likely its COMMIT, can end that wait.
				start := time.Now()
				a := pass(t, c, lookupSQL, explained(orderLookup, nil), false)

				if a.Reject != nil || time.Since(start) != time.Second {
					t.Errorf("got %v after %v; want it run as soon as others waited on it", a.Reject, time.Since(start))
				}
			})
		})
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
	p := mustParse(t, `{"scheduler": {"max_active": 8, "queue_timeout": "2s", "slow_lane": {"max_active": 1, "queue_timeout": "30s"}, "demote_after": "5s",
			"adaptive": {"floor": 2, "backoff": 0.5, "max_slowdown": 3, "lock_wait_share": 0.1}},
		"tenant_defaults": {"budget": {"rate": 10}},
		"tenants": {"acme": {"budget": {"rate": 100, "burst": 1000, "share": 2, "min_charge": 5, "when_over": "slow"}}, "bob": {"mode": "warn"}}}`)

	got := p.SchedConfig()

	want := sched.Config{
		Fast:        sched.Lane{MaxActive: 8, QueueTimeout: 2 * time.Second, StandingAfter: DefaultStandingAfter, StandingTimeout: DefaultStandingTimeout},
		Slow:        sched.Lane{MaxActive: 1, QueueTimeout: 30 * time.Second},
		Budgets:     map[string]sched.Budget{"acme": {Rate: 100, Burst: 1000, Share: 2, MinCharge: 5, WhenOver: sched.SlowLane}},
		Default:     sched.Budget{Rate: 10},
		Controller:  sched.AIMD{Floor: 2, Backoff: 0.5, MaxSlowdown: 3, LockWaitShare: 0.1},
		DemoteAfter: 5 * time.Second,
	}
	if got.Fast != want.Fast || got.Slow != want.Slow || got.Default != want.Default || !maps.Equal(got.Budgets, want.Budgets) ||
		got.Controller != want.Controller || got.DemoteAfter != want.DemoteAfter {
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
		`{"rules": [{"check": "require_where", "functions": ["upper"]}]}`:     "functions",
		`{"unchecked": "maybe"}`:                                              "maybe",
		`{"login_throttle": {"mode": "maybe"}}`:                               "login_throttle",
		`{"learned_timeouts": {"mode": "on", "multiple": 0.5}}`:               "learned_timeouts",
		`{"runaway": {"action": "explode"}}`:                                  "runaway",
		`{"login_throttle": {"failures": -1}}`:                                "login_throttle",
		`{"tenants": {"alice": {"mode": "loud"}}}`:                            "loud",
		`{"max_connections": -1}`:                                             "max_connections",
		`{"tenants": {"alice": {"max_connections": -1}}}`:                     "max_connections",
		`{"rule": []}`:                                                                                 "rule",
		`{"rules": [{"check": "max_cost"}]}`:                                                           "cost",
		`{"rules": [{"check": "max_cost", "cost": -1}]}`:                                               "cost",
		`{"rules": [{"check": "max_scan_rows"}]}`:                                                      "rows",
		`{"rules": [{"check": "require_where", "cost": 5}]}`:                                           "cost",
		`{"rules": [{"check": "max_cost", "cost": 5, "rows": 5}]}`:                                     "rows",
		`{"tenants": {"a": {"budget": {"rate": -1}}}}`:                                                 "rate",
		`{"tenants": {"a": {"budget": {"rate": 10, "when_over": "later"}}}}`:                           "later",
		`{"tenants": {"a": {"budget": {"burst": 10}}}}`:                                                "burst",
		`{"scheduler": {"max_active": 4}, "tenants": {"a": {"budget": {"capacity": 1.5}}}}`:            "capacity",
		`{"scheduler": {"max_active": 4}, "tenants": {"a": {"budget": {"capacity": 0.2, "rate": 5}}}}`: "capacity",
		`{"tenants": {"a": {"budget": {"capacity": 0.2}}}}`:                                            "max_active",
		`{"tenant_defaults": {"statement_timeout": "soon"}}`:                                           "soon",
		`{"tenant_defaults": {"statement_timeout": "-1s"}}`:                                            "statement_timeout",
		`{"tenant_defaults": {"transaction_timeout": "-1s"}}`:                                          "transaction_timeout",
		`{"tenant_defaults": {"mode": "warn"}}`:                                                        "tenant_defaults",
		`{"scheduler": {"max_active": -1}}`:                                                            "max_active",
		`{"rules": [{"check": "deny_ddl", "match": {"clients": ["10.0.0.0/33"]}}]}`:                    "10.0.0.0/33",
		`{"calibration": {"mode": "maybe"}}`:                                                           "maybe",
		`{"calibration": {"credibility": -1}}`:                                                         "credibility",
		`{"calibration": {"returned_mb": -1}}`:                                                         "returned_mb",
		`{"tenant_defaults": {"max_rows": -1}}`:                                                        "max_rows",
		`{"plan_flips": {"mode": "loud"}}`:                                                             "loud",
		`{"plan_flips": {"quarantine": "-1m"}}`:                                                        "quarantine",
		`{"rules": [{"check": "deny_ddl", "match": {"tags": {"route": "/admin"}}}]}`:                   "trusted_roles",
		`{"scheduler": {"adaptive": {}}}`:                                                              "max_active",
		`{"scheduler": {"max_active": 4, "adaptive": {"floor": 8}}}`:                                   "floor",
		`{"scheduler": {"max_active": 4, "adaptive": {"backoff": 1}}}`:                                 "backoff",
		`{"scheduler": {"max_active": 4, "adaptive": {"max_slowdown": 0.5}}}`:                          "max_slowdown",
		`{"scheduler": {"max_active": 4, "adaptive": {"lock_wait_share": -1}}}`:                        "lock_wait_share",
		`{"tenants": {"a": {"priority": "urgent"}}}`:                                                   "urgent",
		`{"ddl_guard": {"mode": "loud"}}`:                                                              "loud",
		`{"ddl_guard": {"lock_timeout": "-1s"}}`:                                                       "lock_timeout",
		`{"scheduler": {"blocker_pays": "maybe"}}`:                                                     "maybe",
		`{"scheduler": {"demote_after": "-1s"}}`:                                                       "demote_after",
		`{"replication_lag": {"max": "-1s"}}`:                                                          "replication_lag",
		`{"mvcc_horizon": {"max_age": "-1s"}}`:                                                         "max_age",
		`{"mvcc_horizon": {"max_age": "1m", "watch": ["jobs"]}}`:                                       "schema.table",
		`{"mvcc_horizon": {"max_age": "1m", "max_dead_tuples": -1}}`:                                   "max_dead_tuples",
		`{"mvcc_horizon": {"watch": ["public.jobs"]}}`:                                                 "max_age",
		`{"scheduler": {"overload_queue": {"mode": "sometimes"}}}`:                                     "sometimes",
		`{"scheduler": {"overload_queue": {"timeout": "-1s"}}}`:                                        "overload_queue",
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

func TestTenantOfFollowsTagsOnlyFromTrustedRoles(t *testing.T) {
	p := mustParse(t, `{"trusted_roles": ["app"]}`)
	for _, tc := range []struct{ role, sql, want string }{
		{"app", "select 1 /*tenant='acme'*/", "acme"},
		{"app", "select 1", "app"},
		{"intruder", "select 1 /*tenant='acme'*/", "intruder"},
	} {
		if got := p.TenantOf(tc.role, tc.sql); got != tc.want {
			t.Errorf("TenantOf(%q, %q) = %q; want %q", tc.role, tc.sql, got, tc.want)
		}
	}
}

func TestBudgetRejectionSaysWhenToRetryWithJitter(t *testing.T) {
	c := gateChecker(t, `{"tenants": {"alice": {"budget": {"rate": 10, "burst": 150, "when_over": "reject"}}}}`, "alice", discard)
	// The first spends 150 and owes 50, five seconds at 10 a second; the second is turned away.
	pass(t, c, "select * from orders where id = 1", costing(200), false)
	seen := map[time.Duration]bool{}
	for range 20 {
		rej := pass(t, c, "select * from orders where id = 1", costing(200), false).Reject
		if rej == nil {
			t.Fatal("statement over budget ran")
		}
		d := retryIn(t, rej.Hint)
		// Refills while the test runs only shorten the wait a little.
		if d < 4*time.Second || d > 7500*time.Millisecond {
			t.Fatalf("retry in %v (%q); want about 5s plus up to half again", d, rej.Hint)
		}
		seen[d] = true
	}
	if len(seen) < 3 {
		t.Errorf("retry hints %v; want them spread by jitter", seen)
	}
}

func TestOverBudgetSaysTheRateInForce(t *testing.T) {
	// A budget by capacity has no rate in the config; the scheduler has the one measured.
	s := sched.New(sched.Config{Budgets: map[string]sched.Budget{"acme": {Rate: 250}, "shut": {Rate: -1}}})
	if rej := overBudget(s, "acme"); !strings.Contains(rej.Detail, "refills at 250 cost units a second") {
		t.Errorf("detail %q; want the scheduler's rate", rej.Detail)
	}
	// A budget shut until the fleet leases a share has nothing to work a wait out from.
	rej := overBudget(s, "shut")
	if !strings.Contains(rej.Detail, "no share") {
		t.Errorf("detail %q; want it to say the instance has no share yet", rej.Detail)
	}
	if d := retryIn(t, rej.Hint); d < time.Second {
		t.Errorf("shut budget retry in %v; want at least a second", d)
	}
}

func TestBusyRejectionSaysWhenToRetry(t *testing.T) {
	if d := retryIn(t, busy(mustParse(t, `{}`), sched.Fast).Hint); d < time.Second || d > 1500*time.Millisecond {
		t.Errorf("busy retry in %v; want about a second", d)
	}
}

// retryIn reads the wait out of a hint saying "Retry in about 2.5s…".
func retryIn(t *testing.T, hint string) time.Duration {
	t.Helper()
	_, rest, ok := strings.Cut(hint, "Retry in about ")
	if !ok {
		t.Fatalf("hint %q gives no time to retry in", hint)
	}
	word, _, _ := strings.Cut(rest, " ")
	d, err := time.ParseDuration(strings.TrimRight(word, ",."))
	if err != nil {
		t.Fatalf("hint %q: %v", hint, err)
	}
	return d
}

func TestDenyFunctionsBlocksSideEffectsEvenInASelect(t *testing.T) {
	c := mustParse(t, `{"rules": [{"check": "deny_functions"}]}`).Checker("alice", discard)
	for sql, blocked := range map[string]bool{
		"select pg_terminate_backend(42)":                     true,
		"select pg_catalog.pg_terminate_backend(42)":          true,
		"select * from dblink_exec('host=x', 'drop table t')": true,
		"select set_config('role', 'admin', false)":           true,
		"select pg_try_advisory_lock(1)":                      true,
		"select lowrite(lo_open(lo_create(0), 131072), 'x')":  true,
		"select pg_wal_replay_pause()":                        true,
		"select * from pg_ls_waldir()":                        true,
		"select pg_drop_replication_slot('s')":                true,
		// It runs the text it is given, which would get round the whole list.
		"select query_to_xml('select pg_terminate_backend(1)', true, false, '')": true,
		"select pg_advisory_xact_lock(1)":                                        false,
		"select upper(name), count(*) from customers group by 1":                 false,
	} {
		rej, _ := c.Check(sql, standard)
		if got := ruleOf(rej) == "deny_functions"; got != blocked {
			t.Errorf("Check(%q) = %v; want blocked %v", sql, rej, blocked)
		}
	}
}

func TestReadOnlyRefusesAnythingButReading(t *testing.T) {
	c := mustParse(t, `{"rules": [{"check": "read_only"}]}`).Checker("agent", discard)
	for sql, blocked := range map[string]bool{
		"select * from orders where id = 1":       false,
		"begin read only":                         false,
		"show search_path":                        false,
		"commit; drop table orders":               true,
		"begin read write":                        true,
		"set default_transaction_read_only = off": true,
		"select nextval('orders_id_seq')":         true,
		"insert into orders values (1)":           true,
	} {
		rej, _ := c.Check(sql, standard)
		if got := ruleOf(rej) == "read_only"; got != blocked {
			t.Errorf("Check(%q) = %v; want blocked %v", sql, rej, blocked)
		}
	}
}

func TestDenyFunctionsTakesItsOwnList(t *testing.T) {
	c := mustParse(t, `{"rules": [{"check": "deny_functions", "functions": ["Upper", "billing.wipe"]}]}`).Checker("alice", discard)
	for sql, blocked := range map[string]bool{
		"select upper('a')":               true,
		"select billing.wipe(1)":          true,
		"select wipe(1)":                  true,
		"select pg_terminate_backend(42)": false,
	} {
		rej, _ := c.Check(sql, standard)
		if got := ruleOf(rej) == "deny_functions"; got != blocked {
			t.Errorf("Check(%q) = %v; want blocked %v", sql, rej, blocked)
		}
	}
}

func TestGateCapsOnlyReads(t *testing.T) {
	config := `{"tenant_defaults": {"max_rows": 1000, "max_bytes": 1048576}}`
	c := gateChecker(t, config, "alice", discard)
	if a := pass(t, c, "select * from orders", costing(1), false); a.MaxRows != 1000 || a.MaxBytes != 1<<20 {
		t.Errorf("read got caps %d rows, %d bytes; want 1000 and 1 MB", a.MaxRows, a.MaxBytes)
	}
	// A write cut short would roll its transaction back.
	if a := pass(t, c, "update orders set total = 0 where id = 1 returning *", costing(1), false); a.MaxRows != 0 || a.MaxBytes != 0 {
		t.Errorf("write got caps %d rows, %d bytes; want none", a.MaxRows, a.MaxBytes)
	}
}

func TestGateChargesTheBytesAStatementReturned(t *testing.T) {
	c := gateChecker(t, `{"tenants": {"alice": {"budget": {"rate": 100, "burst": 100, "when_over": "reject"}}}}`, "alice", discard)
	a := pass(t, c, "select * from orders", costing(10), false)

	// Two MB at 128 units each, after the 10 the plan cost: 266 spent of 100, so 166 owed at 100 a second.
	a.Returned(5000, 2<<20)

	if d := c.Env.Scheduler.RetryAfter("alice"); d < 1600*time.Millisecond || d > 1700*time.Millisecond {
		t.Errorf("owes for %v; want about 1.66s, the plan's cost and 2 MB returned", d)
	}
}

func TestGateChargesAWritesUsualWAL(t *testing.T) {
	c := gateChecker(t, `{"tenants": {"alice": {"budget": {"rate": 100, "burst": 100, "when_over": "reject"}}}}`, "alice", discard)
	var asked []string
	c.Env.WAL = func(database, role, fingerprint string) (float64, bool) {
		asked = append(asked, database+"/"+role)
		return 1 << 20, true
	}

	pass(t, c, "select * from orders where id = 1", costing(10), false)
	if d := c.Env.Scheduler.RetryAfter("alice"); d != 0 {
		t.Fatalf("a read owes for %v; want its WAL not charged", d)
	}
	// A MB of WAL at 128 units, after the 10 the plan cost and the 10 the read did: 148 of 100, so 48 owed.
	pass(t, c, "update orders set total = 0 where id = 1", costing(10), false)

	if d := c.Env.Scheduler.RetryAfter("alice"); d < 470*time.Millisecond || d > 490*time.Millisecond {
		t.Errorf("owes for %v; want about 0.48s", d)
	}
	if !slices.Equal(asked, []string{"shop/alice"}) {
		t.Errorf("asked about %v; want the write's database and role once", asked)
	}
}

func TestCapacityBudgetsReachTheScheduler(t *testing.T) {
	p := mustParse(t, `{"scheduler": {"max_active": 4}, "tenant_defaults": {"budget": {"capacity": 0.1}},
		"tenants": {"reporting": {"budget": {"capacity": 0.2, "when_over": "reject"}}}}`)
	cfg := p.SchedConfig()
	if b := cfg.Budgets["reporting"]; b.Capacity != 0.2 || b.Rate != 0 {
		t.Errorf("reporting budget %+v; want capacity 0.2 and no fixed rate", b)
	}
	if cfg.Default.Capacity != 0.1 {
		t.Errorf("default budget %+v; want capacity 0.1", cfg.Default)
	}
}

func TestLearnedTimeoutIsAMultipleOfTheStatementsP99(t *testing.T) {
	config := `{"learned_timeouts": {"mode": "on", "multiple": 5, "min_runs": 10, "floor": "100ms"},
		"tenant_defaults": {"statement_timeout": "30s"}}`
	for _, tc := range []struct {
		p99  time.Duration
		runs int64
		want time.Duration
	}{
		{200 * time.Millisecond, 50, time.Second},
		{5 * time.Millisecond, 50, 100 * time.Millisecond},
		{200 * time.Millisecond, 5, 30 * time.Second},
		{10 * time.Second, 50, 30 * time.Second},
	} {
		c := gateChecker(t, config, "alice", discard)
		var asked string
		c.Env.P99 = func(database, role, tenant, fingerprint string) (time.Duration, int64) {
			asked = database + "/" + role + "/" + tenant
			return tc.p99, tc.runs
		}
		if a := pass(t, c, "select * from orders where id = 1", costing(1), false); a.Timeout != tc.want {
			t.Errorf("p99 %v over %d runs: timeout %v; want %v", tc.p99, tc.runs, a.Timeout, tc.want)
		}
		if asked != "shop/alice/alice" {
			t.Errorf("asked for %q; want the statement's database, role and tenant", asked)
		}
	}
}

func TestLearnedTimeoutsAreOffByDefault(t *testing.T) {
	c := gateChecker(t, `{"tenant_defaults": {"statement_timeout": "30s"}}`, "alice", discard)
	c.Env.P99 = func(string, string, string, string) (time.Duration, int64) { return time.Millisecond, 1000 }
	if a := pass(t, c, "select 1", costing(1), false); a.Timeout != 30*time.Second {
		t.Errorf("timeout %v; want the tenant's 30s", a.Timeout)
	}
}

func TestWatchKeepsAStatementForItsTime(t *testing.T) {
	var w Watch
	now := time.Now()
	w.add("shop", "fp", "select $1", "57014", 10*time.Minute, now)

	if left, _, ok := w.watched("shop", "fp", now.Add(time.Minute)); !ok || left != 9*time.Minute {
		t.Errorf("watched = %v, %v; want 9m left", left, ok)
	}
	if _, _, ok := w.watched("other", "fp", now); ok {
		t.Error("a statement watched in another database")
	}
	if _, _, ok := w.watched("shop", "fp", now.Add(11*time.Minute)); ok {
		t.Error("still watched after its time")
	}
	if l := w.List(now); len(l) != 1 || l[0].Query != "select $1" || l[0].Reason != "57014" {
		t.Errorf("List = %+v; want the one entry", l)
	}
}

func TestStatementThatBreaksItsTimeoutIsWatched(t *testing.T) {
	config := `{"runaway": {"action": "reject", "watch": "10m"}, "tenant_defaults": {"statement_timeout": "1s"}}`
	c := gateChecker(t, config, "alice", discard)
	c.Env.Runaways = &Watch{}
	const sql = "select * from orders where note like '%x%'"

	a := pass(t, c, sql, costing(1), false)
	// A cancel for another reason, such as the DDL guard's, says nothing about the statement.
	a.Broke(session.Interruption{Code: "55P03"})
	if again := pass(t, c, sql, costing(1), false); again.Reject != nil {
		t.Fatalf("statement rejected after a lock timeout: %v", again.Reject)
	}
	a.Broke(session.Interruption{Code: "57014"})

	rej := pass(t, c, "select * from orders where note like '%y%'", costing(1), false).Reject
	if codeOf(rej) != "53000" || !strings.Contains(rej.Message, "runaway") {
		t.Fatalf("watched statement got %v; want 53000 for a runaway", rej)
	}
	if d := retryIn(t, rej.Hint); d < 9*time.Minute {
		t.Errorf("retry in %v; want about the 10m it is watched", d)
	}
	if other := pass(t, c, "select 1", costing(1), false); other.Reject != nil {
		t.Errorf("another statement got %v; want it run", other.Reject)
	}
}

func TestAFetchOrExecuteIsNeitherWatchedNorTimedByItsText(t *testing.T) {
	config := `{"runaway": {"action": "reject", "watch": "10m"}, "learned_timeouts": {"mode": "on", "min_runs": 10},
		"tenant_defaults": {"statement_timeout": "30s"}}`
	c := gateChecker(t, config, "alice", discard)
	c.Env.Runaways = &Watch{}
	c.Env.P99 = func(string, string, string, string) (time.Duration, int64) { return time.Millisecond, 1000 }

	// Every cursor's FETCH, and every prepared statement's EXECUTE, reads the same, whatever it runs.
	for _, sql := range []string{"fetch 100 from c1", "execute a(1)"} {
		a := pass(t, c, sql, costing(1), false)
		if a.Timeout != 30*time.Second {
			t.Errorf("%s: timeout %v; want the tenant's 30s, not one learned from others with its text", sql, a.Timeout)
		}
		if a.Broke != nil {
			a.Broke(session.Interruption{Code: "57014"})
		}
	}
	for _, sql := range []string{"fetch 100 from c2", "execute b(1)"} {
		if a := pass(t, c, sql, costing(1), false); a.Reject != nil {
			t.Errorf("%s got %v after another with its text broke its timeout; want it run", sql, a.Reject)
		}
	}
}

func TestWatchedStatementCoolsDownInTheSlowLane(t *testing.T) {
	config := `{"runaway": {"action": "slow"}, "scheduler": {"max_active": 1, "queue_timeout": "10ms"}, "tenant_defaults": {"statement_timeout": "1s"}}`
	c := gateChecker(t, config, "alice", discard)
	c.Env.Runaways = &Watch{}
	const sql = "select * from orders where note like '%x%'"
	broke := pass(t, c, sql, costing(1), false)
	broke.Broke(session.Interruption{Code: "54000"})
	broke.Release()
	holder := pass(t, c, "select 1", costing(1), false)
	defer holder.Release()

	// The fast lane's one slot is taken, but the slow lane has room.
	if a := pass(t, c, sql, costing(1), false); a.Reject != nil {
		t.Errorf("watched statement got %v; want it run in the slow lane", a.Reject)
	}
}

func TestAWarnTenantIsOnlyLoggedAsARunaway(t *testing.T) {
	config := `{"runaway": {"action": "slow"}, "learned_timeouts": {"mode": "on", "min_runs": 10},
		"scheduler": {"max_active": 1, "queue_timeout": "10ms"}, "tenants": {"alice": {"mode": "warn", "statement_timeout": "30s"}}}`
	var logs bytes.Buffer
	c := gateChecker(t, config, "alice", slog.New(slog.NewTextHandler(&logs, nil)))
	c.Env.Runaways = &Watch{}
	c.Env.P99 = func(string, string, string, string) (time.Duration, int64) { return time.Millisecond, 1000 }
	const sql = "select * from orders where note like '%x%'"

	broke := pass(t, c, sql, costing(1), false)
	if broke.Timeout != 30*time.Second {
		t.Errorf("timeout %v; want the tenant's 30s, as warn mode only logs", broke.Timeout)
	}
	broke.Broke(session.Interruption{Code: "57014"})
	broke.Release()
	holder := pass(t, c, "select 1", costing(1), false)
	defer holder.Release()

	// Warn mode leaves it in the fast lane, whose one slot is taken, so it would have been turned away there.
	pass(t, c, sql, costing(1), false)
	if !strings.Contains(logs.String(), `rule=busy tenant=alice lane=fast`) {
		t.Errorf("logged %q; want the watched statement kept in the fast lane", logs.String())
	}
}

func TestPlanFlipIsToldToTheStats(t *testing.T) {
	c := gateChecker(t, `{"plan_flips": {"mode": "warn"}, "scheduler": {"slow_lane": {"max_active": 1}}}`, "alice", discard)
	var flipped []string
	c.Env.Flipped = func(database, fingerprint string) { flipped = append(flipped, database+"/"+fingerprint) }
	train(t, c, lookupSQL, explained(orderLookup, nil), 5, time.Millisecond)
	c.Env.Plans = &plan.Cache{RefreshOneIn: -1}

	for range 2 {
		pass(t, c, lookupSQL, explained(orderFullRead, nil), false)
	}

	if want := "shop/" + sqlparse.Fingerprint(lookupSQL); !slices.Equal(flipped, []string{want}) {
		t.Errorf("flips told %q; want the one flip, once", flipped)
	}
}

func TestKilledTenantOrStatementIsTurnedAway(t *testing.T) {
	kills := &Kills{}
	now := time.Now()
	kills.Kill(KillTenant, "acme", now.Add(10*time.Minute))
	kills.Kill(KillFingerprint, sqlparse.Fingerprint("delete from jobs where id = 1"), now.Add(time.Hour))
	// A policy with nothing else to check still turns killed statements away.
	p := mustParse(t, `{"trusted_roles": ["app"]}`)
	check := func(role, sql string) *pgproto3.ErrorResponse {
		c := p.Checker(role, discard)
		c.Env = Env{Database: "shop", Kills: kills}
		rej, _ := c.Check(sql, standard)
		return rej
	}

	if rej := check("acme", "select 1"); codeOf(rej) != "53000" || !strings.Contains(rej.Message, "tenant") {
		t.Errorf("killed tenant got %v; want 53000", rej)
	}
	if rej := check("app", "select 1 /*tenant='acme'*/"); codeOf(rej) != "53000" {
		t.Errorf("killed tenant through a trusted role's tag got %v; want 53000", rej)
	}
	if rej := check("bob", "delete from jobs where id = 7"); codeOf(rej) != "53000" || !strings.Contains(rej.Message, "statement") {
		t.Errorf("killed statement got %v; want 53000", rej)
	}
	if rej := check("bob", "select 1"); rej != nil {
		t.Errorf("another tenant's statement got %v; want it run", rej)
	}
	kills.Unkill(KillTenant, "acme")
	if rej := check("acme", "select 1"); rej != nil {
		t.Errorf("unkilled tenant got %v", rej)
	}
	if l := kills.List(now); len(l) != 1 || l[0].Kind != KillFingerprint {
		t.Errorf("List = %+v; want the statement's kill left", l)
	}
}

func TestKillStopsAStatementPreparedBeforeIt(t *testing.T) {
	kills := &Kills{}
	for _, config := range []string{`{}`, `{"tenants": {"acme": {"statement_timeout": "5s"}}}`} {
		c := mustParse(t, config).Checker("acme", discard)
		c.Env = Env{Database: "shop", Kills: kills, Scheduler: sched.New(sched.Config{})}
		const sql = "select * from orders where id = $1"
		rej, gate := c.Check(sql, standard)
		if rej != nil || gate == nil {
			t.Fatalf("%s: Check = %v and gate %v; want a gate, which each execution of a prepared statement passes", config, rej, gate != nil)
		}

		kills.Kill(KillTenant, "acme", time.Now().Add(time.Minute))
		if a := gate(t.Context(), session.Explain{}, false); codeOf(a.Reject) != "53000" {
			t.Errorf("%s: prepared statement of a killed tenant got %v; want 53000", config, a.Reject)
		}
		kills.Unkill(KillTenant, "acme")
		kills.Kill(KillFingerprint, sqlparse.Fingerprint(sql), time.Now().Add(time.Minute))
		if a := gate(t.Context(), session.Explain{}, false); codeOf(a.Reject) != "53000" {
			t.Errorf("%s: killed prepared statement got %v; want 53000", config, a.Reject)
		}
		kills.Unkill(KillFingerprint, sqlparse.Fingerprint(sql))
		if a := gate(t.Context(), session.Explain{}, false); a.Reject != nil {
			t.Errorf("%s: after the kills ended got %v; want it run", config, a.Reject)
		}
	}
}

func TestKillsEnd(t *testing.T) {
	var kills Kills
	now := time.Now()
	kills.Kill(KillTenant, "acme", now.Add(time.Minute))
	if _, ok := kills.killed(KillTenant, "acme", now.Add(2*time.Minute)); ok {
		t.Error("tenant still killed after its kill ended")
	}
}

func TestAdminRolesMayUseTheConsole(t *testing.T) {
	p := mustParse(t, `{"admin_roles": ["ops"]}`)
	if !p.Admin("ops") || p.Admin("alice") {
		t.Errorf("Admin(ops) = %v, Admin(alice) = %v; want only ops", p.Admin("ops"), p.Admin("alice"))
	}
}

func TestAllowlistLearnsThenEnforces(t *testing.T) {
	list := &Allowlist{}
	checkAs := func(config, role, sql string) *pgproto3.ErrorResponse {
		c := mustParse(t, config).Checker(role, discard)
		c.Env = Env{Database: "shop", Allowlist: list}
		rej, _ := c.Check(sql, standard)
		return rej
	}
	const learn, enforce = `{"allowlist": {"mode": "learn", "roles": ["agent"]}}`, `{"allowlist": {"mode": "enforce", "roles": ["agent"]}}`

	if rej := checkAs(learn, "agent", "select * from orders where id = 1"); rej != nil {
		t.Fatalf("learn mode got %v; want everything run", rej)
	}
	checkAs(learn, "bob", "select * from customers")

	if rej := checkAs(enforce, "agent", "select * from orders where id = 42"); rej != nil {
		t.Errorf("learned statement with another value got %v; want it run", rej)
	}
	if rej := checkAs(enforce, "agent", "delete from orders where id = 1"); codeOf(rej) != "42501" {
		t.Errorf("unlearned statement got %v; want 42501", rej)
	}
	// Roles not listed are neither learned nor held to it.
	if rej := checkAs(enforce, "bob", "delete from orders where id = 1"); rej != nil {
		t.Errorf("unlisted role got %v; want it run", rej)
	}
	if l := list.List(); len(l) != 1 || l[0].Role != "agent" || l[0].Query != "select * from orders where id = $1" {
		t.Errorf("List = %+v; want agent's one statement", l)
	}
}

func TestAllowlistSavesAndLoads(t *testing.T) {
	var a, b Allowlist
	a.learn("agent", "fp1", "select $1")
	var buf bytes.Buffer
	if err := a.Save(&buf); err != nil {
		t.Fatal(err)
	}
	if err := b.Load(&buf); err != nil {
		t.Fatal(err)
	}
	if !b.allowed("agent", "fp1") || b.allowed("agent", "fp2") {
		t.Errorf("loaded allowlist %+v; want fp1 only", b.List())
	}
}

func TestAllowlistStopsLearningWhenFull(t *testing.T) {
	var list Allowlist
	for i := range maxAllowlisted {
		list.learn("agent", strconv.Itoa(i), "select $1")
	}
	if learned, full := list.learn("agent", "one more", "select $1"); learned || !full {
		t.Errorf("learn when full = %v, %v; want it refused and the list said full", learned, full)
	}
	if _, full := list.learn("agent", "and another", "select $1"); full {
		t.Error("full reported twice; want it once, so it is logged once")
	}
}

func TestAllowlistSaveDoesNotHoldUpChecks(t *testing.T) {
	var list Allowlist
	list.learn("agent", "fp", "select $1")
	r, w := io.Pipe()
	defer r.Close()
	go list.Save(w)
	time.Sleep(10 * time.Millisecond)

	// The file is written slowly, as on a busy disk; sessions must still check against the list meanwhile.
	checked := make(chan bool)
	go func() { checked <- list.allowed("agent", "fp") }()
	select {
	case <-checked:
	case <-time.After(time.Second):
		t.Fatal("allowed waited for Save to write")
	}
}
