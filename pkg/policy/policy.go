// Package policy decides which statements may run and how, from rules, tenants and budgets in a JSON config.
package policy

import (
	"cmp"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Avik-creator/queryguard/pkg/plan"
	"github.com/Avik-creator/queryguard/pkg/sched"
	"github.com/Avik-creator/queryguard/pkg/session"
	"github.com/Avik-creator/queryguard/pkg/sqlparse"
	"github.com/jackc/pgx/v5/pgproto3"
)

// defaultTenantTag is the sqlcommenter key that names a statement's tenant.
const defaultTenantTag = "tenant"

// Config is the JSON policy file.
type Config struct {
	// Unchecked is "reject" (the default) to block statements QueryGuard can't check, or "allow" to let them run.
	Unchecked            string            `json:"unchecked"`
	MaxConnections       int               `json:"max_connections"`        // across all tenants; 0 means no cap
	TenantMaxConnections int               `json:"tenant_max_connections"` // for each role without its own; 0 means no cap
	TrustedRoles         []string          `json:"trusted_roles"`          // roles whose statements may name their tenant in a tag
	TenantTag            string            `json:"tenant_tag"`             // the sqlcommenter key naming the tenant; "" means "tenant"
	Scheduler            Scheduler         `json:"scheduler"`
	Calibration          Calibration       `json:"calibration"`
	PlanFlips            PlanFlips         `json:"plan_flips"`
	TenantDefaults       Tenant            `json:"tenant_defaults"` // the budget and timeouts of tenants that set none
	Rules                []Rule            `json:"rules"`
	Tenants              map[string]Tenant `json:"tenants"` // keyed by tenant: a role, or a tag from a trusted role
}

// Rule turns on one check.
type Rule struct {
	Check   string   `json:"check"`
	Mode    Mode     `json:"mode"`
	Schemas []string `json:"schemas"` // for schema_allowlist only
	Cost    float64  `json:"cost"`    // for max_cost only
	Rows    float64  `json:"rows"`    // for max_scan_rows only
	Match   Match    `json:"match"`
}

// Match narrows a rule to some statements: every field that is set must match, so a rule without one matches all.
type Match struct {
	Roles            []string          `json:"roles"`
	Tenants          []string          `json:"tenants"`
	ApplicationNames []string          `json:"application_names"` // application_name is set by the client, so only a label
	Clients          []string          `json:"clients"`           // client addresses or CIDR prefixes
	Tags             map[string]string `json:"tags"`              // sqlcommenter tags, all of which must be on the statement
}

// Tenant holds the settings for one tenant.
type Tenant struct {
	Mode                     Mode     `json:"mode"`                        // warn turns every rejection for this tenant into a log line
	MaxConnections           int      `json:"max_connections"`             // for a role; 0 keeps tenant_max_connections
	Budget                   *Budget  `json:"budget"`                      // nil keeps tenant_defaults' budget
	StatementTimeout         Duration `json:"statement_timeout"`           // the proxy cancels statements running longer; 0 means no limit
	IdleInTransactionTimeout Duration `json:"idle_in_transaction_timeout"` // the proxy ends sessions idle in a transaction longer
}

// Budget is a tenant's allowance of planner cost units; see sched.Budget.
type Budget struct {
	Rate      float64 `json:"rate"`       // units a second; 0 means no limit
	Burst     float64 `json:"burst"`      // units saved up at most; 0 means a second's worth
	Share     float64 `json:"share"`      // weight against other tenants for slots; 0 means 1
	MinCharge float64 `json:"min_charge"` // the least a statement costs
	WhenOver  string  `json:"when_over"`  // queue (the default), slow or reject, once the budget is spent
}

// Scheduler sets the lanes statements run in.
type Scheduler struct {
	MaxActive    int      `json:"max_active"`    // statements running at once; 0 means no limit
	QueueTimeout Duration `json:"queue_timeout"` // the longest a statement waits for its budget or a slot; 0 means 5s
	SlowLane     Lane     `json:"slow_lane"`
}

// Lane is the slow lane's size and patience.
type Lane struct {
	MaxActive    int      `json:"max_active"`    // 0 means no limit
	QueueTimeout Duration `json:"queue_timeout"` // 0 means 60s
}

// Calibration sets how measured run times correct the planner's costs.
type Calibration struct {
	Mode        string  `json:"mode"`        // "on" (the default) charges budgets the calibrated cost; "off" charges the planner's
	Credibility float64 `json:"credibility"` // runs a plan needs before its own timing counts as much as the server's; 0 means 10
}

// PlanFlips sets what happens to a statement whose plan looks like a regression from its usual one.
type PlanFlips struct {
	Mode       Mode     `json:"mode"`       // enforce (the default) runs it in the slow lane; warn only logs it
	Quarantine Duration `json:"quarantine"` // about how long a new plan is held as a flip before it is taken as the usual one; 0 means 10m
}

// Duration is a time.Duration written in JSON as a string such as "5s" or "1m30s".
type Duration time.Duration

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	*d = Duration(v)
	return err
}

func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }

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
type Policy struct {
	cfg       Config
	clients   [][]netip.Prefix // each rule's Match.Clients, parsed
	costRules bool             // some rule judges plans
	needsCost bool             // statements are explained for cost rules, budgets or fair shares of slots
	gated     bool             // budgets, slots or timeouts apply, so every statement passes a gate
}

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
	p := &Policy{cfg: cfg}
	if err := p.compile(); err != nil {
		return nil, err
	}
	return p, nil
}

// compile checks the config and works out what the checks need.
func (p *Policy) compile() error {
	c := &p.cfg
	var errs []error
	if c.Unchecked != "" && c.Unchecked != "allow" && c.Unchecked != "reject" {
		errs = append(errs, fmt.Errorf("unchecked %q: want allow or reject", c.Unchecked))
	}
	if c.MaxConnections < 0 || c.TenantMaxConnections < 0 {
		errs = append(errs, errors.New("max_connections and tenant_max_connections must not be negative"))
	}
	s := c.Scheduler
	if s.MaxActive < 0 || s.SlowLane.MaxActive < 0 || s.QueueTimeout < 0 || s.SlowLane.QueueTimeout < 0 {
		errs = append(errs, errors.New("scheduler: max_active and queue_timeout must not be negative"))
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
		prefixes, err := parsePrefixes(r.Match.Clients)
		if err != nil {
			errs = append(errs, fmt.Errorf("check %s: %w", r.Check, err))
		}
		p.clients = append(p.clients, prefixes)
		p.costRules = p.costRules || checks[r.Check].overBy != nil
	}
	if c.TenantDefaults.Mode != "" || c.TenantDefaults.MaxConnections != 0 {
		errs = append(errs, errors.New("tenant_defaults: mode and max_connections belong to each tenant; use tenant_max_connections"))
	}
	errs = append(errs, c.TenantDefaults.validate("tenant_defaults"))
	budgeted := c.TenantDefaults.Budget != nil
	timed := c.TenantDefaults.StatementTimeout > 0 || c.TenantDefaults.IdleInTransactionTimeout > 0
	for name, t := range c.Tenants {
		if !t.Mode.valid() {
			errs = append(errs, fmt.Errorf("tenant %s: mode %q: want enforce or warn", name, t.Mode))
		}
		if t.MaxConnections < 0 {
			errs = append(errs, fmt.Errorf("tenant %s: max_connections must not be negative", name))
		}
		errs = append(errs, t.validate("tenant "+name))
		budgeted = budgeted || t.Budget != nil
		timed = timed || t.StatementTimeout > 0 || t.IdleInTransactionTimeout > 0
	}
	if m := c.Calibration.Mode; m != "" && m != "on" && m != "off" {
		errs = append(errs, fmt.Errorf("calibration mode %q: want on or off", m))
	}
	if c.Calibration.Credibility < 0 {
		errs = append(errs, errors.New("calibration credibility must not be negative"))
	}
	if !c.PlanFlips.Mode.valid() {
		errs = append(errs, fmt.Errorf("plan_flips mode %q: want enforce or warn", c.PlanFlips.Mode))
	}
	if c.PlanFlips.Quarantine < 0 {
		errs = append(errs, errors.New("plan_flips quarantine must not be negative"))
	}
	slots := s.MaxActive > 0 || s.SlowLane.MaxActive > 0
	// Fair shares of slots go by cost too, so limited slots need plans as budgets do.
	p.needsCost = p.costRules || budgeted || slots
	p.gated = budgeted || timed || slots
	return errors.Join(errs...)
}

// validate checks a tenant's budget and timeouts.
func (t Tenant) validate(name string) error {
	var errs []error
	if t.StatementTimeout < 0 || t.IdleInTransactionTimeout < 0 {
		errs = append(errs, fmt.Errorf("%s: statement_timeout and idle_in_transaction_timeout must not be negative", name))
	}
	if b := t.Budget; b != nil {
		if b.Rate < 0 || b.Burst < 0 || b.Share < 0 || b.MinCharge < 0 {
			errs = append(errs, fmt.Errorf("%s: budget rate, burst, share and min_charge must not be negative", name))
		}
		if b.Burst > 0 && b.Rate == 0 {
			errs = append(errs, fmt.Errorf("%s: a budget's burst needs a rate", name))
		}
		if !slices.Contains([]string{"", string(sched.Queue), string(sched.SlowLane), string(sched.Reject)}, b.WhenOver) {
			errs = append(errs, fmt.Errorf("%s: budget when_over %q: want queue, slow or reject", name, b.WhenOver))
		}
	}
	return errors.Join(errs...)
}

// parsePrefixes reads client addresses and CIDR prefixes; an address stands for itself alone.
func parsePrefixes(clients []string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, c := range clients {
		if a, err := netip.ParseAddr(c); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("client %q: want an address or a CIDR prefix", c)
		}
		prefixes = append(prefixes, p.Masked())
	}
	return prefixes, nil
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

// SchedConfig returns the lanes and budgets for the scheduler.
func (p *Policy) SchedConfig() sched.Config {
	s := p.cfg.Scheduler
	cfg := sched.Config{
		Fast:    sched.Lane{MaxActive: s.MaxActive, QueueTimeout: time.Duration(s.QueueTimeout)},
		Slow:    sched.Lane{MaxActive: s.SlowLane.MaxActive, QueueTimeout: time.Duration(s.SlowLane.QueueTimeout)},
		Budgets: map[string]sched.Budget{},
		Default: p.cfg.TenantDefaults.Budget.sched(),
	}
	for name, t := range p.cfg.Tenants {
		if t.Budget != nil {
			cfg.Budgets[name] = t.Budget.sched()
		}
	}
	return cfg
}

func (b *Budget) sched() sched.Budget {
	if b == nil {
		return sched.Budget{}
	}
	return sched.Budget{Rate: b.Rate, Burst: b.Burst, Share: b.Share, MinCharge: b.MinCharge, WhenOver: sched.Action(b.WhenOver)}
}

// tuning returns how the plan history judges.
func (p *Policy) tuning() plan.Tuning {
	return plan.Tuning{Credibility: p.cfg.Calibration.Credibility, Quarantine: time.Duration(p.cfg.PlanFlips.Quarantine)}
}

// tenant returns a tenant's settings, with tenant_defaults' budget and timeouts where it sets none.
func (p *Policy) tenant(name string) Tenant {
	t, d := p.cfg.Tenants[name], p.cfg.TenantDefaults
	t.Budget = cmp.Or(t.Budget, d.Budget)
	t.StatementTimeout = cmp.Or(t.StatementTimeout, d.StatementTimeout)
	t.IdleInTransactionTimeout = cmp.Or(t.IdleInTransactionTimeout, d.IdleInTransactionTimeout)
	return t
}

// Holder holds the policy in force; Store replaces it for every Checker it made, so a reload reaches open sessions.
type Holder struct{ p atomic.Pointer[Policy] }

func (h *Holder) Load() *Policy   { return h.p.Load() }
func (h *Holder) Store(p *Policy) { h.p.Store(p) }

// Checker returns a checker for one session of role that always follows the policy in force.
func (h *Holder) Checker(role string, log *slog.Logger) *Checker {
	return newChecker(h.Load, role, log)
}

// Checker returns the statement checker for one session of role, logging to log.
func (p *Policy) Checker(role string, log *slog.Logger) *Checker {
	return newChecker(func() *Policy { return p }, role, log)
}

func newChecker(policy func() *Policy, role string, log *slog.Logger) *Checker {
	return &Checker{policy: policy, role: role, log: log.With("role", role)}
}

// TableSizes knows the planner's row count of each table, and whether its statistics are stale.
type TableSizes interface {
	Rows(database string, t plan.Table) (rows float64, known bool)
	Stale(database string, t plan.Table) bool
}

// Env is what a Checker works with besides its policy.
type Env struct {
	Database  string           // the session's database, part of every plan's cache key
	Client    netip.Addr       // the client's address, for rules that match on it
	Plans     *plan.Cache      // shared by every session; nil gives the Checker a cache of its own
	History   *plan.History    // shared by every session; nil gives the Checker a history of its own
	Tables    TableSizes       // needed by max_scan_rows; nil leaves every table's size unknown
	Scheduler *sched.Scheduler // shared by every session; nil admits every statement at once
}

// Checker checks the statements of one session; only the session's own goroutine uses it.
type Checker struct {
	Env Env

	policy    func() *Policy
	role      string
	log       *slog.Logger
	warnedTag bool // the role sent a tenant tag it isn't trusted to send, which was logged once
}

// subject is who a statement runs for and where it comes from, as rules match it.
type subject struct {
	role, tenant, app string
	client            netip.Addr
	tags              map[string]string
}

// Check returns the error to send instead of running sql, or nil, and the gate it passes just before it executes, if any.
func (c *Checker) Check(sql string, set session.Settings) (*pgproto3.ErrorResponse, session.Gate) {
	p := c.policy()
	if len(p.cfg.Rules) == 0 && !p.gated {
		return nil, nil
	}
	tags := sqlparse.Tags(sql)
	who := subject{role: c.role, tenant: c.tenant(p, tags), app: set.ApplicationName, client: c.Env.Client, tags: tags}
	warn := p.cfg.Tenants[who.tenant].Mode == Warn

	reason := misread(sql, set)
	var q sqlparse.Query
	if reason == "" {
		var err error
		if q, err = sqlparse.Analyze(sql); err != nil {
			reason = "The parser cannot read it: " + err.Error()
		}
	}
	if reason != "" {
		// A statement that can't be read can still be scheduled, though it can't be explained or judged.
		if rej := c.unchecked(p, warn, reason); rej != nil || !p.gated {
			return rej, nil
		}
		return nil, c.gate(p, sql, sqlparse.Query{}, who)
	}

	var fingerprint string
	blocked := c.judge(p, who, warn, "statement", func(r Rule) bool {
		f := checks[r.Check].violatedBy
		return f != nil && f(q, r)
	}, func() []any {
		fingerprint = sqlparse.Fingerprint(sql)
		return []any{"tenant", who.tenant, "fingerprint", fingerprint, "query", sqlparse.Normalize(sql)}
	})
	if blocked != nil {
		return rejection("42501", "queryguard: rule "+blocked.Check+" blocks this statement", "Statement fingerprint "+fingerprint+".",
			checks[blocked.Check].hint), nil
	}
	// EXPLAIN plans one statement at a time, and a later statement may need what an earlier one creates.
	if !p.gated && !(p.costRules && (q.Explainable || q.DDL || q.Analyzes)) {
		return nil, nil
	}
	return nil, c.gate(p, sql, q, who)
}

// tenant returns who a statement runs for: the tenant its tag names when the role is trusted to name one, else the role.
func (c *Checker) tenant(p *Policy, tags map[string]string) string {
	name := tags[cmp.Or(p.cfg.TenantTag, defaultTenantTag)]
	switch {
	case name == "":
		return c.role
	case slices.Contains(p.cfg.TrustedRoles, c.role):
		return name
	}
	if !c.warnedTag {
		c.warnedTag = true
		c.log.Warn("ignored a tenant tag from a role not trusted to name one", "tag", name)
	}
	return c.role
}

// gate admits sql when it is about to execute: it waits for the tenant's budget, judges the plan, and takes a slot.
func (c *Checker) gate(p *Policy, sql string, q sqlparse.Query, who subject) session.Gate {
	return func(ctx context.Context, e session.Explain, running bool) session.Admission {
		t := p.tenant(who.tenant)
		warn := t.Mode == Warn
		a := session.Admission{Timeout: time.Duration(t.StatementTimeout), IdleInTransaction: time.Duration(t.IdleInTransactionTimeout)}
		s := c.Env.Scheduler

		// The budget is looked at before EXPLAIN, the dearest step, and spent once the cost is known.
		if s != nil && !warn {
			if _, err := s.Reserve(ctx, who.tenant); err != nil {
				c.log.Warn("rejected statement", "rule", "budget", "tenant", who.tenant, "err", err)
				return session.Admission{Reject: overBudget(t.Budget)}
			}
		}

		var cost float64
		var flipped bool
		// A session that can't explain the statement here passes no Run, and it is judged without a plan.
		if q.Explainable && e.Run != nil && (p.costRules || (s != nil && p.needsCost)) {
			fingerprint := sqlparse.Fingerprint(sql)
			pl, rej, ok := c.plan(p, sql, fingerprint, who, warn, e)
			switch {
			case rej != nil:
				return session.Admission{Reject: rej}
			case !ok:
				// Postgres refused the statement, so it won't run; the session passes the error on.
				return session.Admission{}
			}
			cost = pl.Cost
			// A generic plan standing in for one with values too large to send twice says nothing of how the statement runs,
			// and nor does opening a cursor, whose query runs in later FETCHes.
			if !e.Generic && !q.Cursor {
				cost, flipped, a.Ran = c.learn(p, sql, fingerprint, who, warn, pl)
			}
		}
		if q.DDL || q.Analyzes {
			// Plans may change once the statement is committed, so they are explained again; forgetting them sooner would let
			// another session cache an old plan in between.
			plans, prefix := c.plans(), c.Env.Database+"\x00"
			a.Settled = func() { plans.Forget(func(k string) bool { return strings.HasPrefix(k, prefix) }) }
		}
		if s == nil {
			return a
		}

		lane := sched.Fast
		if warn {
			if s.Spent(who.tenant) {
				c.log.Warn("would reject statement", "rule", "budget", "tenant", who.tenant)
			}
			s.Charge(who.tenant, cost)
		} else {
			l, err := s.Spend(ctx, who.tenant, cost)
			if err != nil {
				c.log.Warn("rejected statement", "rule", "budget", "tenant", who.tenant, "cost", cost, "err", err)
				return session.Admission{Reject: overBudget(t.Budget)}
			}
			lane = l
		}
		if flipped {
			lane = sched.Slow
		}
		if !running {
			release, err := s.Acquire(ctx, who.tenant, lane)
			switch {
			case err != nil && warn:
				c.log.Warn("would reject statement", "rule", "busy", "tenant", who.tenant, "lane", lane)
			case err != nil:
				s.Refund(who.tenant, cost)
				c.log.Warn("rejected statement", "rule", "busy", "tenant", who.tenant, "lane", lane, "err", err)
				return session.Admission{Reject: busy(p, lane)}
			default:
				a.Release = release
			}
		}
		return a
	}
}

// plan gets sql's plan, cached or explained by the session, and judges it by the cost rules; ok is false when Postgres refused sql.
func (c *Checker) plan(p *Policy, sql, fingerprint string, who subject, warn bool, e session.Explain) (_ plan.Plan, rej *pgproto3.ErrorResponse, ok bool) {
	// A generic plan holds for any values.
	key := c.statementKey(fingerprint) + "\x00" + strconv.FormatBool(e.Generic)
	pl, err := c.plans().Get(key, func() (plan.Plan, error) {
		out, err := e.Run()
		if err != nil {
			return plan.Plan{}, err
		}
		return plan.Parse(out)
	})
	switch {
	case errors.Is(err, session.ErrNoPlan):
		return plan.Plan{}, nil, false
	case err != nil:
		return plan.Plan{}, c.unchecked(p, warn, "Its plan could not be read: "+err.Error()), true
	}
	rows := func(t plan.Table) (float64, bool) {
		if c.Env.Tables == nil {
			return 0, false
		}
		return c.Env.Tables.Rows(c.Env.Database, t)
	}
	blocked := c.judge(p, who, warn, "statement", func(r Rule) bool {
		f := checks[r.Check].overBy
		return f != nil && f(pl, rows, r) != ""
	}, func() []any {
		return []any{"tenant", who.tenant, "fingerprint", fingerprint, "query", sqlparse.Normalize(sql), "cost", pl.Cost, "seq_scans", pl.SeqScans}
	})
	if blocked == nil {
		return pl, nil, true
	}
	why := checks[blocked.Check].overBy(pl, rows, *blocked)
	return pl, rejection("54000", "queryguard: rule "+blocked.Check+" blocks this statement",
		"Statement fingerprint "+fingerprint+". "+why, checks[blocked.Check].hint), true
}

// learn looks pl up in its statement's history; it returns the cost to charge, whether to run it in the slow lane, and what to record once it ran.
func (c *Checker) learn(p *Policy, sql, fingerprint string, who subject, warn bool, pl plan.Plan) (cost float64, slow bool, ran func(time.Duration, bool)) {
	if c.Env.History == nil {
		c.Env.History = &plan.History{}
	}
	history, plans, tune, key := c.Env.History, c.plans(), p.tuning(), c.statementKey(fingerprint)
	v := history.Judge(key, pl, tune)
	cost = pl.Cost
	if p.cfg.Calibration.Mode != "off" {
		cost *= v.Factor
	}
	if v.Flip != "" {
		slow = p.cfg.PlanFlips.Mode != Warn && !warn && c.Env.Scheduler != nil
		if v.First {
			c.log.Warn("plan flip", append([]any{"rule", "plan_flips", "tenant", who.tenant, "fingerprint", fingerprint,
				"query", sqlparse.Normalize(sql), "why", v.Flip, "cost", pl.Cost, "slow_lane", slow}, c.stale(pl)...)...)
		}
	}
	return cost, slow, func(took time.Duration, finished bool) {
		if !history.Ran(key, pl, took, finished, tune) {
			return
		}
		// The cached plan may be out of date, as after an index was dropped, so the statement is explained again.
		plans.Forget(func(k string) bool { return strings.HasPrefix(k, key+"\x00") })
		c.log.Warn("statement ran far slower than its plan predicts", append([]any{"tenant", who.tenant, "fingerprint", fingerprint,
			"took", took, "cost", pl.Cost}, c.stale(pl)...)...)
	}
}

// stale returns log attributes naming the tables pl reads whose statistics are stale, a likely cause of a bad plan.
func (c *Checker) stale(pl plan.Plan) []any {
	if c.Env.Tables == nil {
		return nil
	}
	var stale []plan.Table
	for _, t := range slices.Concat(pl.SeqScans, pl.Indexed) {
		if c.Env.Tables.Stale(c.Env.Database, t) {
			stale = append(stale, t)
		}
	}
	if stale == nil {
		return nil
	}
	return []any{"stale_tables", stale, "hint", "Run ANALYZE on them."}
}

// statementKey names a statement in the plan cache and history: plans differ by database and, through row-level security, by role.
func (c *Checker) statementKey(fingerprint string) string {
	return strings.Join([]string{c.Env.Database, c.role, fingerprint}, "\x00")
}

// plans returns the plan cache, making one of the Checker's own when it has none.
func (c *Checker) plans() *plan.Cache {
	if c.Env.Plans == nil {
		c.Env.Plans = &plan.Cache{}
	}
	return c.Env.Plans
}

// CheckStartup checks the settings a client asks for at login, which no statement shows; it returns a FATAL error to refuse the login.
func (c *Checker) CheckStartup(settings iter.Seq2[string, string]) *pgproto3.ErrorResponse {
	p := c.policy()
	who := subject{role: c.role, tenant: c.role, client: c.Env.Client}
	warn := p.cfg.Tenants[c.role].Mode == Warn
	all := maps.Collect(settings)
	who.app = all["application_name"]
	for name, value := range all {
		if name != "search_path" {
			continue
		}
		q := sqlparse.Query{Schemas: sqlparse.SearchPath(value)}
		blocked := c.judge(p, who, warn, "login", func(r Rule) bool {
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

// judge logs every rule matching who that violated reports, with what describe returns, and returns the first that blocks, or nil.
func (c *Checker) judge(p *Policy, who subject, warn bool, what string, violated func(Rule) bool, describe func() []any) (blocked *Rule) {
	var attrs []any
	for i, r := range p.cfg.Rules {
		if !p.matches(i, who) || !violated(r) {
			continue
		}
		if attrs == nil {
			attrs = describe()
		}
		msg := "would reject " + what
		if r.Mode != Warn && !warn {
			msg = "rejected " + what
			if blocked == nil {
				blocked = &p.cfg.Rules[i]
			}
		}
		c.log.Warn(msg, append([]any{"rule", r.Check}, attrs...)...)
	}
	return blocked
}

// matches reports whether rule i applies to who.
func (p *Policy) matches(i int, who subject) bool {
	m := p.cfg.Rules[i].Match
	listed := func(list []string, v string) bool { return len(list) == 0 || slices.Contains(list, v) }
	client := len(p.clients[i]) == 0 || slices.ContainsFunc(p.clients[i], func(pr netip.Prefix) bool { return pr.Contains(who.client.Unmap()) })
	for k, v := range m.Tags {
		if who.tags[k] != v {
			return false
		}
	}
	return client && listed(m.Roles, who.role) && listed(m.Tenants, who.tenant) && listed(m.ApplicationNames, who.app)
}

// CheckTooLong decides on a statement too long to read, as for one the parser can't read.
func (c *Checker) CheckTooLong(size int) *pgproto3.ErrorResponse {
	p := c.policy()
	return c.unchecked(p, p.cfg.Tenants[c.role].Mode == Warn, fmt.Sprintf("It is too long to read: %d bytes.", size))
}

// unchecked logs a statement that could not be checked, and why, and rejects it unless unchecked is allow or no rule applies.
func (c *Checker) unchecked(p *Policy, warn bool, reason string) *pgproto3.ErrorResponse {
	if len(p.cfg.Rules) == 0 {
		return nil
	}
	reject := p.cfg.Unchecked != "allow" && !warn
	c.log.Warn("could not check statement", "reason", reason, "rejected", reject)
	if !reject {
		return nil
	}
	// The reason's own text may quote the statement, so the client gets only the fixed part before the colon.
	detail, _, _ := strings.Cut(reason, ":")
	if !strings.HasSuffix(detail, ".") {
		detail += "."
	}
	return rejection("42501", "queryguard: statement could not be checked", detail,
		"QueryGuard rejects statements it cannot check unless unchecked is allow in its config.")
}

// overBudget is the error for a statement whose tenant's budget is spent.
func overBudget(b *Budget) *pgproto3.ErrorResponse {
	detail := "The tenant's cost budget is spent."
	if b != nil {
		detail = fmt.Sprintf("The tenant's cost budget is spent; it refills at %.0f cost units a second.", b.Rate)
	}
	return rejection("53000", "queryguard: tenant is over its cost budget", detail, "Retry later, or run fewer or cheaper statements.")
}

// busy is the error for a statement that found no free slot in time.
func busy(p *Policy, lane sched.LaneID) *pgproto3.ErrorResponse {
	wait := cmp.Or(time.Duration(p.cfg.Scheduler.QueueTimeout), sched.DefaultQueueTimeout)
	if lane == sched.Slow {
		wait = cmp.Or(time.Duration(p.cfg.Scheduler.SlowLane.QueueTimeout), sched.DefaultSlowQueueTimeout)
	}
	return rejection("53000", "queryguard: too busy to run the statement",
		fmt.Sprintf("No slot in the %s lane came free within %s.", lane, wait), "Retry later.")
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

// rejection is an error with code 42501 (insufficient_privilege), 53000 (insufficient_resources) or 54000 (program_limit_exceeded).
func rejection(code, message, detail, hint string) *pgproto3.ErrorResponse {
	return &pgproto3.ErrorResponse{
		Severity: "ERROR", SeverityUnlocalized: "ERROR", Code: code,
		Message: message, Detail: detail, Hint: hint,
	}
}
