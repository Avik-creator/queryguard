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
	"strconv"
	"strings"

	"github.com/Avik-creator/queryguard/pkg/plan"
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
	Cost    float64  `json:"cost"`    // for max_cost only
	Rows    float64  `json:"rows"`    // for max_scan_rows only
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

// check is one kind of rule, judging the statement or its plan; hint and why are fixed text, since DO blocks carry them into SQL.
type check struct {
	violatedBy func(q sqlparse.Query, r Rule) bool
	overBy     func(p plan.Plan, rows func(plan.Table) (float64, bool), r Rule) (why string)
	hint       string
}

var checks = map[string]check{
	"deny_ddl": {
		violatedBy: func(q sqlparse.Query, _ Rule) bool { return q.DDL || q.Do },
		hint:       "Schema changes and DO blocks are not allowed for this role.",
	},
	"require_where": {
		violatedBy: func(q sqlparse.Query, _ Rule) bool { return q.ChangesEveryRow },
		hint:       "Add a WHERE clause. WHERE true changes every row on purpose; TRUNCATE is blocked too.",
	},
	"index_concurrently": {
		violatedBy: func(q sqlparse.Query, _ Rule) bool { return q.BlockingIndexChange },
		hint: "Use CONCURRENTLY with CREATE INDEX, DROP INDEX and REINDEX so writes are not blocked. " +
			"Index a partitioned table with CREATE INDEX ON ONLY, then each partition concurrently.",
	},
	"schema_allowlist": {
		violatedBy: func(q sqlparse.Query, r Rule) bool {
			// A search_path set from a run-time value could name any schema.
			return q.UnknownSearchPath || slices.ContainsFunc(q.Schemas, func(s string) bool {
				return !systemSchema(s) && !slices.Contains(r.Schemas, s)
			})
		},
		hint: "Only the schemas allowed for this role may be named.",
	},
	"max_cost": {
		overBy: func(p plan.Plan, _ func(plan.Table) (float64, bool), r Rule) string {
			if p.Cost <= r.Cost {
				return ""
			}
			return fmt.Sprintf("Its planned cost, %.0f, is over the limit of %.0f.", p.Cost, r.Cost)
		},
		hint: "Make the statement cheaper, for example with an index that fits its WHERE clause.",
	},
	"max_scan_rows": {
		overBy: func(p plan.Plan, rows func(plan.Table) (float64, bool), r Rule) string {
			// Reading a small table in full is the right plan, so only the rows read in full count, over every table and partition.
			var total float64
			for _, t := range p.SeqScans {
				if n, ok := rows(t); ok {
					total += n
				}
			}
			if total <= r.Rows {
				return ""
			}
			return fmt.Sprintf("It reads about %.0f rows in full; the limit is %.0f.", total, r.Rows)
		},
		hint: "Add an index that fits the WHERE clause, so the plan does not read whole tables.",
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
		case checks[r.Check].violatedBy == nil && checks[r.Check].overBy == nil:
			errs = append(errs, fmt.Errorf("unknown check %q", r.Check))
		case seen[r.Check]:
			errs = append(errs, fmt.Errorf("check %s is listed twice", r.Check))
		case !r.Mode.valid():
			errs = append(errs, fmt.Errorf("check %s: mode %q: want enforce or warn", r.Check, r.Mode))
		case (r.Check == "schema_allowlist") != (len(r.Schemas) > 0):
			errs = append(errs, fmt.Errorf("check %s: schemas are needed by schema_allowlist and allowed only there", r.Check))
		case !limit(r.Check == "max_cost", r.Cost):
			errs = append(errs, fmt.Errorf("check %s: a positive cost limit is needed by max_cost and allowed only there", r.Check))
		case !limit(r.Check == "max_scan_rows", r.Rows):
			errs = append(errs, fmt.Errorf("check %s: a positive rows limit is needed by max_scan_rows and allowed only there", r.Check))
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

// limit reports whether a rule's limit v is set when it is needed and only then.
func limit(needed bool, v float64) bool {
	if needed {
		return v > 0
	}
	return v == 0
}

// NeedsCatalog reports whether a rule needs table sizes.
func (p *Policy) NeedsCatalog() bool {
	return slices.ContainsFunc(p.cfg.Rules, func(r Rule) bool { return r.Check == "max_scan_rows" })
}

// ConnectionLimits returns the cap on all sessions and on role's sessions; 0 means no cap.
func (p *Policy) ConnectionLimits(role string) (total, tenant int) {
	return p.cfg.MaxConnections, cmp.Or(p.cfg.Tenants[role].MaxConnections, p.cfg.TenantMaxConnections)
}

// Checker returns the statement checker for one session of role, logging to log.
func (p *Policy) Checker(role string, log *slog.Logger) *Checker {
	return &Checker{
		role:           role,
		costRules:      slices.ContainsFunc(p.cfg.Rules, func(r Rule) bool { return checks[r.Check].overBy != nil }),
		rules:          p.cfg.Rules,
		allowUnchecked: p.cfg.Unchecked == "allow",
		warnOnly:       p.cfg.Tenants[role].Mode == Warn,
		log:            log.With("role", role),
	}
}

// TableSizes knows the planner's row count of each table.
type TableSizes interface {
	Rows(database string, t plan.Table) (rows float64, known bool)
}

// Costs says where a Checker gets plans and table sizes for its cost rules.
type Costs struct {
	Database string      // the session's database, part of every plan's cache key
	Plans    *plan.Cache // shared by every session; nil gives the Checker a cache of its own
	Tables   TableSizes  // needed by max_scan_rows; nil leaves every table's size unknown
}

// Checker checks the statements of one session.
type Checker struct {
	Costs Costs

	role           string
	costRules      bool
	rules          []Rule
	allowUnchecked bool
	warnOnly       bool
	log            *slog.Logger
}

// Check returns the error to send instead of running sql, or nil, and its cost check when a cost rule applies; matches are logged.
func (c *Checker) Check(sql string, set session.Settings) (*pgproto3.ErrorResponse, session.CostCheck) {
	if len(c.rules) == 0 {
		return nil, nil
	}
	if reason := misread(sql, set); reason != "" {
		return c.unchecked(reason), nil
	}
	q, err := sqlparse.Analyze(sql)
	if err != nil {
		return c.unchecked("The parser cannot read it.", "err", err), nil
	}
	var fingerprint string
	blocked := c.judge("statement", func(r Rule) bool {
		f := checks[r.Check].violatedBy
		return f != nil && f(q, r)
	}, func() []any {
		fingerprint = sqlparse.Fingerprint(sql)
		return []any{"fingerprint", fingerprint, "query", sqlparse.Normalize(sql)}
	})
	if blocked != nil {
		return rejection("42501", "queryguard: rule "+blocked.Check+" blocks this statement", "Statement fingerprint "+fingerprint+".",
			checks[blocked.Check].hint), nil
	}
	// EXPLAIN plans one statement at a time, and a later statement may need what an earlier one creates.
	if !c.costRules || !q.Explainable {
		return nil, nil
	}
	return nil, c.costCheck(sql)
}

// costCheck judges sql on its plan, taken from the cache or explained by the session.
func (c *Checker) costCheck(sql string) session.CostCheck {
	fingerprint := sqlparse.Fingerprint(sql)
	return func(e session.Explain) *pgproto3.ErrorResponse {
		if c.Costs.Plans == nil {
			c.Costs.Plans = &plan.Cache{}
		}
		// Plans differ by database and, through row-level security, by role; a generic plan holds for any values.
		key := strings.Join([]string{c.Costs.Database, c.role, fingerprint, strconv.FormatBool(e.Generic)}, "\x00")
		p, err := c.Costs.Plans.Get(key, func() (plan.Plan, error) {
			out, err := e.Run()
			if err != nil {
				return plan.Plan{}, err
			}
			return plan.Parse(out)
		})
		switch {
		case errors.Is(err, session.ErrNoPlan):
			// Postgres refused the statement; the session passes that error on instead.
			return nil
		case err != nil:
			return c.unchecked("Its plan could not be read.", "err", err)
		}
		blocked := c.judge("statement", func(r Rule) bool {
			f := checks[r.Check].overBy
			return f != nil && f(p, c.rows, r) != ""
		}, func() []any {
			return []any{"fingerprint", fingerprint, "query", sqlparse.Normalize(sql), "cost", p.Cost, "seq_scans", p.SeqScans}
		})
		if blocked == nil {
			return nil
		}
		why := checks[blocked.Check].overBy(p, c.rows, *blocked)
		return rejection("54000", "queryguard: rule "+blocked.Check+" blocks this statement",
			"Statement fingerprint "+fingerprint+". "+why, checks[blocked.Check].hint)
	}
}

// rows returns a table's size in the session's database.
func (c *Checker) rows(t plan.Table) (float64, bool) {
	if c.Costs.Tables == nil {
		return 0, false
	}
	return c.Costs.Tables.Rows(c.Costs.Database, t)
}

// CheckStartup checks the settings a client asks for at login, which no statement shows; it returns a FATAL error to refuse the login.
func (c *Checker) CheckStartup(settings iter.Seq2[string, string]) *pgproto3.ErrorResponse {
	for name, value := range settings {
		if name != "search_path" {
			continue
		}
		q := sqlparse.Query{Schemas: sqlparse.SearchPath(value)}
		blocked := c.judge("login", func(r Rule) bool {
			f := checks[r.Check].violatedBy
			return f != nil && f(q, r)
		}, func() []any { return []any{"search_path", value} })
		if blocked != nil {
			e := rejection("42501", "queryguard: rule "+blocked.Check+" blocks this search_path", "", checks[blocked.Check].hint)
			e.Severity, e.SeverityUnlocalized = "FATAL", "FATAL"
			return e
		}
	}
	return nil
}

// judge logs every rule violated reports, with what describe returns, and returns the first one that blocks, or nil.
func (c *Checker) judge(what string, violated func(Rule) bool, describe func() []any) (blocked *Rule) {
	var attrs []any
	for i, r := range c.rules {
		if !violated(r) {
			continue
		}
		if attrs == nil {
			attrs = describe()
		}
		msg := "would reject " + what
		if r.Mode != Warn && !c.warnOnly {
			msg = "rejected " + what
			if blocked == nil {
				blocked = &c.rules[i]
			}
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
	return rejection("42501", "queryguard: statement could not be checked", reason,
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

// rejection is an error with code 42501 (insufficient_privilege, as Postgres refuses actions) or 54000 (program_limit_exceeded).
func rejection(code, message, detail, hint string) *pgproto3.ErrorResponse {
	return &pgproto3.ErrorResponse{
		Severity: "ERROR", SeverityUnlocalized: "ERROR", Code: code,
		Message: message, Detail: detail, Hint: hint,
	}
}
