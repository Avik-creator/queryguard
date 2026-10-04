package policy

import (
	"bytes"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
		got := c.Check(sql, standard)
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
		if got := c.Check(sql, standard); (ruleOf(got) == "index_concurrently") != blocked {
			t.Errorf("Check(%q) = %v; want blocked = %v", sql, got, blocked)
		}
	}
}

func TestRejectionCarriesOnlyFixedTextAndFingerprint(t *testing.T) {
	c := mustParse(t, allRules).Checker("alice", discard)

	got := c.Check("delete from orders -- it's O'Brien's", standard)

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

	if got := c.Check("delete from orders where false; delete from orders", standard); got != nil {
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

	c.Check("delete from orders", standard)

	if !strings.Contains(logs.String(), `msg="rejected statement"`) || !strings.Contains(logs.String(), "rule=require_where") {
		t.Errorf("log %q; want the rejection", logs.String())
	}
}

func TestTenantInWarnModeIsNeverBlocked(t *testing.T) {
	p := mustParse(t, `{"rules": [{"check": "require_where"}], "tenants": {"reporting": {"mode": "warn"}}}`)

	if got := p.Checker("reporting", discard).Check("delete from orders", standard); got != nil {
		t.Errorf("tenant in warn mode got %v; want allowed", got)
	}
	if got := p.Checker("alice", discard).Check("delete from orders", standard); got == nil {
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

		got := c.Check("selec 1", standard)

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

		got := c.Check(tc.sql, tc.set)

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
		`{"rule": []}`: "rule",
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
	if p.Checker("alice", discard).Check("delete from orders", standard) == nil {
		t.Error("loaded policy allowed DELETE without WHERE")
	}
}

var discard = slog.New(slog.DiscardHandler)

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
