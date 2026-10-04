package policy

import (
	"bytes"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Avik-creator/queryguard/pkg/plan"
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
		if _, cost := c.Check(sql, standard); (cost != nil) != want {
			t.Errorf("Check(%q) gave a cost check = %v; want %v", sql, cost != nil, want)
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

		got := cost(explained(tc.out, nil))

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

	got := cost(explained(`[{"Plan": {"Node Type": "Seq Scan", "Schema": "public", "Relation Name": "orders", "Total Cost": 500}}]`, nil))

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
	c := costChecker(t, costRules, nil, discard)
	runs := 0
	for _, sql := range []string{"select * from orders where id = 1", "select * from orders where id = 2"} {
		_, cost := c.Check(sql, standard)
		cost(session.Explain{Run: func() (string, error) {
			runs++
			return `[{"Plan": {"Node Type": "Index Scan", "Total Cost": 8}}]`, nil
		}})
	}
	_, cost := c.Check("select * from orders where id = 3", standard)
	cost(session.Explain{Generic: true, Run: func() (string, error) {
		runs++
		return `[{"Plan": {"Node Type": "Index Scan", "Total Cost": 8}}]`, nil
	}})

	// The same statement with other constants hits the cache; a generic plan is a different plan.
	if runs != 2 {
		t.Errorf("explained %d times; want 2", runs)
	}
	if s := c.Costs.Plans.Stats(); s.Hits != 1 || s.Misses != 2 {
		t.Errorf("cache stats %+v; want 1 hit, 2 misses", s)
	}
}

func TestCostCheckWithoutPlan(t *testing.T) {
	c := costChecker(t, costRules, nil, discard)
	_, cost := c.Check("select * from orders", standard)
	if got := cost(explained("", session.ErrNoPlan)); got != nil {
		t.Errorf("statement Postgres refused got %v; want it left to the session", got)
	}

	_, cost = c.Check("select * from customers", standard)
	if got := cost(explained("not json", nil)); got == nil || got.Message != "queryguard: statement could not be checked" {
		t.Errorf("unreadable plan got %v; want rejected unchecked", got)
	}
}

func TestCostRulesInWarnMode(t *testing.T) {
	var logs bytes.Buffer
	c := costChecker(t, `{"rules": [{"check": "max_cost", "cost": 10, "mode": "warn"}]}`, nil, logger(&logs))
	_, cost := c.Check("select * from orders", standard)

	if got := cost(explained(`[{"Plan": {"Node Type": "Seq Scan", "Total Cost": 500}}]`, nil)); got != nil {
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
		`{"rule": []}`:                                             "rule",
		`{"rules": [{"check": "max_cost"}]}`:                       "cost",
		`{"rules": [{"check": "max_cost", "cost": -1}]}`:           "cost",
		`{"rules": [{"check": "max_scan_rows"}]}`:                  "rows",
		`{"rules": [{"check": "require_where", "cost": 5}]}`:       "cost",
		`{"rules": [{"check": "max_cost", "cost": 5, "rows": 5}]}`: "rows",
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
func rejected(e *pgproto3.ErrorResponse, _ session.CostCheck) *pgproto3.ErrorResponse { return e }

// costChecker checks alice's statements in database shop with a fresh plan cache and the given table sizes.
func costChecker(t *testing.T, config string, sizes tables, log *slog.Logger) *Checker {
	t.Helper()
	c := mustParse(t, config).Checker("alice", log)
	c.Costs = Costs{Database: "shop", Plans: &plan.Cache{}, Tables: sizes}
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
