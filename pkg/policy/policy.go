// Package policy decides which statements may run, from rules in a JSON config.
package policy

import (
	"cmp"
	"encoding/json/v2"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"os"
	"slices"
	"strings"

	"github.com/Avik-creator/queryguard/pkg/session"
	"github.com/Avik-creator/queryguard/pkg/sqlparse"
	"github.com/jackc/pgx/v5/pgproto3"
)

// Config is the JSON policy file.
type Config struct {
	// Unchecked is "reject" (the default) to block statements QueryGuard can't check, or "allow" to let them run.
	Unchecked            string            `json:"unchecked"`
	MaxConnections       int               `json:"max_connections"`        // across all tenants; 0 means no cap
	TenantMaxConnections int               `json:"tenant_max_connections"` // for each tenant without its own; 0 means no cap
	Rules                []Rule            `json:"rules"`
	Tenants              map[string]Tenant `json:"tenants"` // keyed by role
}

// Rule turns on one check.
type Rule struct {
	Check   string   `json:"check"`
	Mode    Mode     `json:"mode"`
	Schemas []string `json:"schemas"` // for schema_allowlist only
}

// Tenant holds the settings for one role.
type Tenant struct {
	Mode           Mode `json:"mode"`            // warn turns every rejection for this role into a log line
	MaxConnections int  `json:"max_connections"` // 0 keeps tenant_max_connections
}

// Mode says whether a match blocks the statement or only logs it.
type Mode string

const (
	Enforce Mode = "enforce" // the default
	Warn    Mode = "warn"
)

func (m Mode) valid() bool { return m == "" || m == Enforce || m == Warn }

// check is one kind of rule; hint is fixed text, since rejections inside a transaction carry it into SQL.
type check struct {
	violatedBy func(q sqlparse.Query, r Rule) bool
	hint       string
}

var checks = map[string]check{
	"deny_ddl": {
		func(q sqlparse.Query, _ Rule) bool { return q.DDL || q.Do },
		"Schema changes and DO blocks are not allowed for this role.",
	},
	"require_where": {
		func(q sqlparse.Query, _ Rule) bool { return q.ChangesEveryRow },
		"Add a WHERE clause. WHERE true changes every row on purpose; TRUNCATE is blocked too.",
	},
	"index_concurrently": {
		func(q sqlparse.Query, _ Rule) bool { return q.BlockingIndexChange },
		"Use CONCURRENTLY with CREATE INDEX, DROP INDEX and REINDEX so writes are not blocked. " +
			"Index a partitioned table with CREATE INDEX ON ONLY, then each partition concurrently.",
	},
	"schema_allowlist": {
		func(q sqlparse.Query, r Rule) bool {
			// A search_path set from a run-time value could name any schema.
			return q.UnknownSearchPath || slices.ContainsFunc(q.Schemas, func(s string) bool {
				return !systemSchema(s) && !slices.Contains(r.Schemas, s)
			})
		},
		"Only the schemas allowed for this role may be named.",
	},
}

// systemSchema reports whether s is always allowed: drivers and tools read the catalogs, and pg_temp (pg_temp_N) is the session's own.
func systemSchema(s string) bool {
	return s == "pg_catalog" || s == "information_schema" || strings.HasPrefix(s, "pg_temp")
}

// Policy is a checked Config.
type Policy struct{ cfg Config }

// Load reads and checks the policy file at path.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Parse reads a policy from JSON, rejecting unknown fields and invalid settings.
func Parse(data []byte) (*Policy, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg, json.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Policy{cfg}, nil
}

func (c *Config) validate() error {
	var errs []error
	if c.Unchecked != "" && c.Unchecked != "allow" && c.Unchecked != "reject" {
		errs = append(errs, fmt.Errorf("unchecked %q: want allow or reject", c.Unchecked))
	}
	if c.MaxConnections < 0 || c.TenantMaxConnections < 0 {
		errs = append(errs, errors.New("max_connections and tenant_max_connections must not be negative"))
	}
	seen := map[string]bool{}
	for _, r := range c.Rules {
		switch {
		case checks[r.Check].violatedBy == nil:
			errs = append(errs, fmt.Errorf("unknown check %q", r.Check))
		case seen[r.Check]:
			errs = append(errs, fmt.Errorf("check %s is listed twice", r.Check))
		case !r.Mode.valid():
			errs = append(errs, fmt.Errorf("check %s: mode %q: want enforce or warn", r.Check, r.Mode))
		case (r.Check == "schema_allowlist") != (len(r.Schemas) > 0):
			errs = append(errs, fmt.Errorf("check %s: schemas are needed by schema_allowlist and allowed only there", r.Check))
		}
		seen[r.Check] = true
	}
	for role, t := range c.Tenants {
		if !t.Mode.valid() {
			errs = append(errs, fmt.Errorf("tenant %s: mode %q: want enforce or warn", role, t.Mode))
		}
		if t.MaxConnections < 0 {
			errs = append(errs, fmt.Errorf("tenant %s: max_connections must not be negative", role))
		}
	}
	return errors.Join(errs...)
}

// ConnectionLimits returns the cap on all sessions and on role's sessions; 0 means no cap.
func (p *Policy) ConnectionLimits(role string) (total, tenant int) {
	return p.cfg.MaxConnections, cmp.Or(p.cfg.Tenants[role].MaxConnections, p.cfg.TenantMaxConnections)
}

// Checker returns the statement checker for one session of role, logging to log.
func (p *Policy) Checker(role string, log *slog.Logger) *Checker {
	return &Checker{
		rules:          p.cfg.Rules,
		allowUnchecked: p.cfg.Unchecked == "allow",
		warnOnly:       p.cfg.Tenants[role].Mode == Warn,
		log:            log.With("role", role),
	}
}

// Checker checks the statements of one session.
type Checker struct {
	rules          []Rule
	allowUnchecked bool
	warnOnly       bool
	log            *slog.Logger
}

// Check returns the error to send instead of running sql, or nil to run it; every match is logged.
func (c *Checker) Check(sql string, set session.Settings) *pgproto3.ErrorResponse {
	if len(c.rules) == 0 {
		return nil
	}
	if reason := misread(sql, set); reason != "" {
		return c.unchecked(reason)
	}
	q, err := sqlparse.Analyze(sql)
	if err != nil {
		return c.unchecked("The parser cannot read it.", "err", err)
	}
	var fingerprint string
	blocked := c.judge(q, "statement", func() []any {
		fingerprint = sqlparse.Fingerprint(sql)
		return []any{"fingerprint", fingerprint, "query", sqlparse.Normalize(sql)}
	})
	if blocked == "" {
		return nil
	}
	return rejection("queryguard: rule "+blocked+" blocks this statement", "Statement fingerprint "+fingerprint+".", checks[blocked].hint)
}

// CheckStartup checks the settings a client asks for at login, which no statement shows; it returns a FATAL error to refuse the login.
func (c *Checker) CheckStartup(settings iter.Seq2[string, string]) *pgproto3.ErrorResponse {
	for name, value := range settings {
		if name != "search_path" {
			continue
		}
		blocked := c.judge(sqlparse.Query{Schemas: sqlparse.SearchPath(value)}, "login", func() []any { return []any{"search_path", value} })
		if blocked != "" {
			e := rejection("queryguard: rule "+blocked+" blocks this search_path", "", checks[blocked].hint)
			e.Severity, e.SeverityUnlocalized = "FATAL", "FATAL"
			return e
		}
	}
	return nil
}

// judge runs the rules on q, logging each match of a statement or login with what describe returns, and returns the first rule that blocks it.
func (c *Checker) judge(q sqlparse.Query, what string, describe func() []any) (blocked string) {
	var attrs []any
	for _, r := range c.rules {
		if !checks[r.Check].violatedBy(q, r) {
			continue
		}
		if attrs == nil {
			attrs = describe()
		}
		msg := "would reject " + what
		if r.Mode != Warn && !c.warnOnly {
			msg = "rejected " + what
			blocked = cmp.Or(blocked, r.Check)
		}
		c.log.Warn(msg, append([]any{"rule", r.Check}, attrs...)...)
	}
	return blocked
}

// CheckTooLong decides on a statement too long to read, as for one the parser can't read.
func (c *Checker) CheckTooLong(size int) *pgproto3.ErrorResponse {
	if len(c.rules) == 0 {
		return nil
	}
	return c.unchecked("It is too long to read.", "size", size)
}

// unchecked logs a statement that could not be checked, and why, and rejects it unless unchecked is allow.
func (c *Checker) unchecked(reason string, attrs ...any) *pgproto3.ErrorResponse {
	reject := !c.allowUnchecked && !c.warnOnly
	c.log.Warn("could not check statement", append([]any{"reason", reason, "rejected", reject}, attrs...)...)
	if !reject {
		return nil
	}
	return rejection("queryguard: statement could not be checked", reason,
		"QueryGuard rejects statements it cannot check unless unchecked is allow in its config.")
}

// sameBytes are the client encodings Postgres reads without converting, so its parser sees the bytes QueryGuard's does.
var sameBytes = []string{"UTF8", "SQL_ASCII"}

// misread says why Postgres may read sql differently from the parser, which assumes the default settings, or returns "".
func misread(sql string, set session.Settings) string {
	switch {
	case set.StandardConformingStrings != "on" && sqlparse.BackslashInString(sql):
		return "Its backslashes may be escapes, since standard_conforming_strings is off or may change."
	case !slices.Contains(sameBytes, set.ClientEncoding) && !ascii(sql):
		// In SJIS, BIG5 and GBK the second byte of a character can be a backslash or a letter.
		return "Its non-ASCII bytes may read differently, since client_encoding is not UTF8 or may change."
	}
	return ""
}

func ascii(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// rejection is an insufficient_privilege error, the code Postgres itself uses for a refused action.
func rejection(message, detail, hint string) *pgproto3.ErrorResponse {
	return &pgproto3.ErrorResponse{
		Severity: "ERROR", SeverityUnlocalized: "ERROR", Code: "42501",
		Message: message, Detail: detail, Hint: hint,
	}
}
