// Package policy decides which statements may run and how, from rules, tenants and budgets in a JSON config.
package policy

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
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

// priorityTag is the sqlcommenter key that sets a statement's priority.
const priorityTag = "priority"

// priorities are the names of sched's priorities; a tenant that names none is normal.
var priorities = map[string]sched.Priority{"critical": sched.Critical, "normal": sched.Normal, "best_effort": sched.BestEffort}

// Config is the JSON policy file.
type Config struct {
	// Unchecked is "reject" (the default) to block statements QueryGuard can't check, or "allow" to let them run.
	Unchecked            string            `json:"unchecked"`
	MaxConnections       int               `json:"max_connections"`        // across all tenants; 0 means no cap
	TenantMaxConnections int               `json:"tenant_max_connections"` // for each role without its own; 0 means no cap
	TrustedRoles         []string          `json:"trusted_roles"`          // roles whose statements may name their tenant in a tag
	AdminRoles           []string          `json:"admin_roles"`            // roles besides superusers that may use the admin console
	TenantTag            string            `json:"tenant_tag"`             // the sqlcommenter key naming the tenant; "" means "tenant"
	Scheduler            Scheduler         `json:"scheduler"`
	Calibration          Calibration       `json:"calibration"`
	PlanFlips            PlanFlips         `json:"plan_flips"`
	DDLGuard             DDLGuard          `json:"ddl_guard"`
	ReplicationLag       ReplicationLag    `json:"replication_lag"`
	MVCCHorizon          Horizon           `json:"mvcc_horizon"`
	LoginThrottle        LoginThrottle     `json:"login_throttle"`
	LearnedTimeouts      LearnedTimeouts   `json:"learned_timeouts"`
	Runaway              Runaway           `json:"runaway"`
	Allowlist            AllowlistConfig   `json:"allowlist"`
	TenantDefaults       Tenant            `json:"tenant_defaults"` // the budget and timeouts of tenants that set none
	Rules                []Rule            `json:"rules"`
	Tenants              map[string]Tenant `json:"tenants"` // keyed by tenant: a role, or a tag from a trusted role
}

// Rule turns on one check.
type Rule struct {
	Check   string   `json:"check"`
	Mode    Mode     `json:"mode"`
	Schemas []string `json:"schemas"` // for schema_allowlist only
	// Functions are the functions deny_functions blocks, by name; none means deniedFunctions, the side-effecting built-ins.
	Functions []string `json:"functions"`
	Cost      float64  `json:"cost"` // for max_cost only
	Rows      float64  `json:"rows"` // for max_scan_rows only
	Match     Match    `json:"match"`
}

// Match narrows a rule to some statements: every field that is set must match, so a rule without one matches all.
type Match struct {
	Roles            []string          `json:"roles"`
	Tenants          []string          `json:"tenants"`
	ApplicationNames []string          `json:"application_names"` // application_name is set by the client, so only a label
	Clients          []string          `json:"clients"`           // client addresses or CIDR prefixes
	Tags             map[string]string `json:"tags"`              // sqlcommenter tags, all of which must be on a trusted role's statement
}

// Tenant holds the settings for one tenant.
type Tenant struct {
	Mode                     Mode     `json:"mode"`                        // warn turns every rejection for this tenant into a log line
	Priority                 string   `json:"priority"`                    // critical, normal (the default) or best_effort, shed first under overload
	MaxConnections           int      `json:"max_connections"`             // for a role; 0 keeps tenant_max_connections
	Budget                   *Budget  `json:"budget"`                      // nil keeps tenant_defaults' budget
	StatementTimeout         Duration `json:"statement_timeout"`           // the proxy cancels statements running longer; 0 means no limit
	IdleInTransactionTimeout Duration `json:"idle_in_transaction_timeout"` // the proxy ends sessions idle in a transaction longer
	TransactionTimeout       Duration `json:"transaction_timeout"`         // the proxy ends sessions whose transaction lasts longer, idle or not
	// MaxRows and MaxBytes cancel a read run outside a transaction once it has returned more rows or bytes of rows; 0 means no cap.
	MaxRows  int64 `json:"max_rows"`
	MaxBytes int64 `json:"max_bytes"`
}

// Budget is a tenant's allowance of planner cost units; see sched.Budget.
type Budget struct {
	Rate      float64 `json:"rate"`       // units a second; 0 means no limit
	Burst     float64 `json:"burst"`      // units saved up at most; 0 means a second's worth
	Share     float64 `json:"share"`      // weight against other tenants for slots; 0 means 1
	MinCharge float64 `json:"min_charge"` // the least a statement costs
	WhenOver  string  `json:"when_over"`  // queue (the default), slow or reject, once the budget is spent
	// Capacity is the budget as a share of the server's measured capacity, such as 0.2 for a fifth, in place of a fixed rate.
	Capacity float64 `json:"capacity"`
}

// Scheduler sets the lanes statements run in.
type Scheduler struct {
	MaxActive    int       `json:"max_active"`    // statements running at once; 0 means no limit
	QueueTimeout Duration  `json:"queue_timeout"` // the longest a statement waits for its budget or a slot; 0 means 5s
	SlowLane     Lane      `json:"slow_lane"`
	Adaptive     *Adaptive `json:"adaptive"`     // moves the limit between a floor and max_active by how the server copes; nil keeps max_active
	BlockerPays  string    `json:"blocker_pays"` // "on" (the default) charges a tenant for the time others wait on its locks; "off" doesn't
	DemoteAfter  Duration  `json:"demote_after"` // a fast-lane statement running longer counts in the slow lane; 0 means never
	// OverloadQueue sets how the fast lane's queue behaves once it stands, as under overload.
	OverloadQueue OverloadQueue `json:"overload_queue"`
}

// Defaults for the fast lane's overload queue.
const (
	DefaultStandingAfter   = time.Second
	DefaultStandingTimeout = 500 * time.Millisecond
)

// OverloadQueue makes a queue that has not been empty for StandingAfter serve its newest statements first and turn away those
// that waited longer than Timeout, as in Facebook's adaptive LIFO with CoDel.
type OverloadQueue struct {
	Mode          string   `json:"mode"`           // "on" (the default) or "off", which keeps every queue first in, first out
	StandingAfter Duration `json:"standing_after"` // 0 means 1s
	Timeout       Duration `json:"timeout"`        // 0 means 500ms
}

// DefaultRunawayWatch is how long a statement that broke its timeout or row cap stays on the watch list.
const DefaultRunawayWatch = 10 * time.Minute

// Runaway sets what happens to a statement, by fingerprint, after one of its runs was cancelled for its timeout or a cap, as TiDB's
// runaway queries do.
type Runaway struct {
	Action string   `json:"action"` // log (the default) logs it running again, slow runs it in the slow lane, reject turns it away; off watches nothing
	Watch  Duration `json:"watch"`  // how long it is watched; 0 means 10m
}

// maxWatched is how many statements the watch list holds; past it, the one whose watch ends soonest goes.
const maxWatched = 10000

// Watch is the runaway watch list, shared by every session; its zero value is ready.
type Watch struct {
	mu      sync.Mutex
	entries map[watchKey]*WatchEntry
}

type watchKey struct{ database, fingerprint string }

// WatchEntry is a watched statement.
type WatchEntry struct {
	Database, Fingerprint, Query string
	Reason                       string // the SQLSTATE of the cancel that put it there: 57014 for its timeout, 54000 for a cap
	Until                        time.Time
	seen                         bool // it has run again since, which was logged
}

// add watches a statement for d.
func (w *Watch) add(database, fingerprint, query, reason string, d time.Duration, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.entries == nil {
		w.entries = map[watchKey]*WatchEntry{}
	}
	maps.DeleteFunc(w.entries, func(_ watchKey, e *WatchEntry) bool { return !now.Before(e.Until) })
	if len(w.entries) >= maxWatched {
		var soonest watchKey
		for k, e := range w.entries {
			if w.entries[soonest] == nil || e.Until.Before(w.entries[soonest].Until) {
				soonest = k
			}
		}
		delete(w.entries, soonest)
	}
	w.entries[watchKey{database, fingerprint}] = &WatchEntry{Database: database, Fingerprint: fingerprint, Query: query, Reason: reason,
		Until: now.Add(d)}
}

// watched returns how long a statement is still watched, and whether this is its first run since it was put there.
func (w *Watch) watched(database, fingerprint string, now time.Time) (left time.Duration, first, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	e := w.entries[watchKey{database, fingerprint}]
	if e == nil || !now.Before(e.Until) {
		return 0, false, false
	}
	first, e.seen = !e.seen, true
	return e.Until.Sub(now), first, true
}

// empty reports whether nothing is watched, so a statement needn't be fingerprinted to be looked up.
func (w *Watch) empty() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.entries) == 0
}

// List returns the statements watched at now, the soonest to leave first.
func (w *Watch) List(now time.Time) []WatchEntry {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []WatchEntry
	for _, e := range w.entries {
		if now.Before(e.Until) {
			out = append(out, *e)
		}
	}
	slices.SortFunc(out, func(a, b WatchEntry) int { return a.Until.Compare(b.Until) })
	return out
}

// Remove takes a statement off the watch list and reports whether it was on it.
func (w *Watch) Remove(database, fingerprint string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	k := watchKey{database, fingerprint}
	_, ok := w.entries[k]
	delete(w.entries, k)
	return ok
}

// AllowlistConfig sets the learned allowlist, as ProxySQL's firewall whitelist: learn each role's statements, then run only those.
type AllowlistConfig struct {
	Mode  string   `json:"mode"`  // learn records each statement of the roles; enforce rejects any not recorded; off (the default) does neither
	Roles []string `json:"roles"` // the roles it applies to, such as an AI agent's or a reporting role; none means every role
}

// applies reports whether the allowlist learns or enforces statements of role.
func (a AllowlistConfig) applies(role string) bool {
	return (a.Mode == "learn" || a.Mode == "enforce") && (len(a.Roles) == 0 || slices.Contains(a.Roles, role))
}

// Allowlist holds each role's learned statements, by fingerprint; its zero value is empty and ready.
type Allowlist struct {
	mu    sync.Mutex
	roles map[string]map[string]string // role to fingerprint to the statement's text, with its constants as $1, $2…
	dirty bool
}

// AllowlistEntry is one learned statement.
type AllowlistEntry struct{ Role, Fingerprint, Query string }

// learn records a role's statement and reports whether it is new.
func (a *Allowlist) learn(role, fingerprint, query string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.roles == nil {
		a.roles = map[string]map[string]string{}
	}
	if a.roles[role] == nil {
		a.roles[role] = map[string]string{}
	}
	if _, ok := a.roles[role][fingerprint]; ok {
		return false
	}
	a.roles[role][fingerprint] = query
	a.dirty = true
	return true
}

// allowed reports whether a role's statement was learned.
func (a *Allowlist) allowed(role, fingerprint string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.roles[role][fingerprint]
	return ok
}

// List returns every learned statement, by role and then fingerprint.
func (a *Allowlist) List() []AllowlistEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []AllowlistEntry
	for role, prints := range a.roles {
		for fp, q := range prints {
			out = append(out, AllowlistEntry{Role: role, Fingerprint: fp, Query: q})
		}
	}
	slices.SortFunc(out, func(x, y AllowlistEntry) int {
		return cmp.Or(cmp.Compare(x.Role, y.Role), cmp.Compare(x.Fingerprint, y.Fingerprint))
	})
	return out
}

// Changed reports whether anything was learned since the last call, so it needs saving.
func (a *Allowlist) Changed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	changed := a.dirty
	a.dirty = false
	return changed
}

// Save writes the allowlist as JSON: role to fingerprint to the statement's text.
func (a *Allowlist) Save(w io.Writer) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return json.MarshalWrite(w, a.roles, jsontext.WithIndent("  "))
}

// Load replaces the allowlist with one Save wrote.
func (a *Allowlist) Load(r io.Reader) error {
	var roles map[string]map[string]string
	if err := json.UnmarshalRead(r, &roles); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.roles = roles
	return nil
}

// KillKind says what a kill blocks.
type KillKind string

const (
	KillTenant      KillKind = "tenant"      // every statement of a tenant
	KillFingerprint KillKind = "fingerprint" // every statement with a fingerprint, from any tenant
)

// Kill is a tenant or statement blocked until a time.
type Kill struct {
	Kind  KillKind
	Name  string // the tenant, or the statement's fingerprint
	Until time.Time
}

// Kills is the kill switch: tenants and statements blocked by an operator, without a change to the config; its zero value is ready.
type Kills struct {
	mu    sync.Mutex
	until map[Kill]time.Time // keyed by Kind and Name, with Until zero
}

// Kill blocks kind name until a time, replacing any kill of it.
func (k *Kills) Kill(kind KillKind, name string, until time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.until == nil {
		k.until = map[Kill]time.Time{}
	}
	k.until[Kill{Kind: kind, Name: name}] = until
}

// Unkill lifts a kill and reports whether there was one.
func (k *Kills) Unkill(kind KillKind, name string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	key := Kill{Kind: kind, Name: name}
	_, ok := k.until[key]
	delete(k.until, key)
	return ok
}

// killed returns how long kind name is still blocked at now.
func (k *Kills) killed(kind KillKind, name string, now time.Time) (time.Duration, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	until, ok := k.until[Kill{Kind: kind, Name: name}]
	if !ok || !now.Before(until) {
		return 0, false
	}
	return until.Sub(now), true
}

// empty reports whether nothing is killed, which spares parsing statements to look them up.
func (k *Kills) empty() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	maps.DeleteFunc(k.until, func(_ Kill, until time.Time) bool { return !time.Now().Before(until) })
	return len(k.until) == 0
}

// List returns the kills in force at now, the soonest to end first.
func (k *Kills) List(now time.Time) []Kill {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []Kill
	for key, until := range k.until {
		if now.Before(until) {
			key.Until = until
			out = append(out, key)
		}
	}
	slices.SortFunc(out, func(a, b Kill) int { return cmp.Or(a.Until.Compare(b.Until), cmp.Compare(a.Name, b.Name)) })
	return out
}

// Defaults for learned timeouts.
const (
	DefaultTimeoutMultiple = 10
	DefaultTimeoutMinRuns  = 100
	DefaultTimeoutFloor    = time.Second
)

// LearnedTimeouts give each statement a timeout of a multiple of its own p99, within its tenant's statement_timeout.
type LearnedTimeouts struct {
	Mode     string   `json:"mode"`     // "on", or "off" (the default)
	Multiple float64  `json:"multiple"` // of the p99; 0 means 10
	MinRuns  int64    `json:"min_runs"` // timed runs needed before the p99 is trusted; 0 means 100
	Floor    Duration `json:"floor"`    // the shortest timeout learned; 0 means 1s
}

// timeout returns the timeout learned from a statement's p99 over runs; false until it has run min_runs times.
func (l LearnedTimeouts) timeout(p99 time.Duration, runs int64) (time.Duration, bool) {
	if runs < cmp.Or(l.MinRuns, DefaultTimeoutMinRuns) || p99 <= 0 {
		return 0, false
	}
	learned := time.Duration(cmp.Or(l.Multiple, DefaultTimeoutMultiple) * float64(p99))
	return max(learned, cmp.Or(time.Duration(l.Floor), DefaultTimeoutFloor)), true
}

// Defaults for the login throttle.
const (
	DefaultLoginFailures = 10
	DefaultLoginWindow   = time.Minute
	DefaultLoginCoolOff  = time.Minute
)

// LoginThrottle refuses logins at the proxy, before they take a Postgres connection, from an address and role that keep failing.
type LoginThrottle struct {
	Mode     string   `json:"mode"`     // "on" (the default) or "off"
	Failures int      `json:"failures"` // failed logins within window that start a cool-off; 0 means 10
	Window   Duration `json:"window"`   // 0 means 1m
	CoolOff  Duration `json:"cool_off"` // how long logins are refused; 0 means 1m
}

// LoginThrottle returns the login throttle with its defaults filled in; Failures is 0 when it is off.
func (p *Policy) LoginThrottle() LoginThrottle {
	t := p.cfg.LoginThrottle
	if t.Mode == "off" {
		return LoginThrottle{Mode: "off"}
	}
	return LoginThrottle{Mode: "on", Failures: cmp.Or(t.Failures, DefaultLoginFailures),
		Window: cmp.Or(t.Window, Duration(DefaultLoginWindow)), CoolOff: cmp.Or(t.CoolOff, Duration(DefaultLoginCoolOff))}
}

// ReplicationLag holds best-effort statements back while a standby lags.
type ReplicationLag struct {
	Max Duration `json:"max"` // the most any standby may lag in replaying; 0 means lag isn't watched
}

// DefaultMaxDeadTuples is how far the watched tables' dead tuples may grow under an old snapshot when max_dead_tuples is zero.
const DefaultMaxDeadTuples = 1000

// Horizon limits the tenant whose old snapshot holds back the MVCC horizon, so vacuum can't clean up after anyone.
type Horizon struct {
	MaxAge        Duration `json:"max_age"`         // a snapshot older than this limits its tenant to one statement at a time; 0 means not watched
	Watch         []string `json:"watch"`           // schema.table names, such as a job queue, whose dead tuples must also grow; none means age alone
	MaxDeadTuples float64  `json:"max_dead_tuples"` // how far they may grow while the snapshot is old; 0 means 1000
}

// DefaultDDLLockTimeout is how long DDL may wait on a lock when the DDL guard sets no lock_timeout.
const DefaultDDLLockTimeout = 2 * time.Second

// DDLGuard sets what happens to DDL waiting on a lock, which makes every later statement on its table queue behind it.
type DDLGuard struct {
	Mode        Mode     `json:"mode"`         // enforce (the default) cancels such DDL; warn only logs it; off does neither
	LockTimeout Duration `json:"lock_timeout"` // how long DDL may wait on a lock with nothing queued behind it; 0 means 2s
}

// Adaptive sets the AIMD limiter; see sched.AIMD.
type Adaptive struct {
	Floor         int     `json:"floor"`           // the lowest limit; 0 means 1
	Backoff       float64 `json:"backoff"`         // what the limit is multiplied by when overloaded; 0 means 0.9
	MaxSlowdown   float64 `json:"max_slowdown"`    // how many times slower than usual statements run before that is overload; 0 means 2
	LockWaitShare float64 `json:"lock_wait_share"` // the share of the limit waiting on locks that is overload; 0 means 0.25
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
	ReturnedMB  float64 `json:"returned_mb"` // cost units charged for each MB of rows a statement returns; 0 means 128
	WALMB       float64 `json:"wal_mb"`      // cost units charged for each MB of WAL a write usually writes; 0 means 128
}

// DefaultWALMB is the cost of writing a MB of WAL, as for writing it to disk in order.
const DefaultWALMB = 128

// DefaultReturnedMB is the cost of returning a MB of rows: reading it from disk in order, 128 pages at seq_page_cost 1.
const DefaultReturnedMB = 128

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
		violatedBy: func(q sqlparse.Query, _ Rule) bool { return q.DDL || q.Opaque },
		hint:       "Schema changes, DO blocks and procedure calls are not allowed for this role.",
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
	"deny_functions": {
		violatedBy: func(q sqlparse.Query, r Rule) bool {
			denied := r.Functions
			if len(denied) == 0 {
				denied = deniedFunctions
			}
			// A schema in front doesn't change what a function does, and a call without one finds it on search_path.
			return slices.ContainsFunc(q.Functions, func(f string) bool {
				return slices.ContainsFunc(denied, func(d string) bool { return strings.EqualFold(bareName(d), bareName(f)) })
			})
		},
		hint: "This function changes state outside the statement or reads the server's files, and is not allowed for this role.",
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

// deniedFunctions are the built-ins with effects beyond the statement's own rows: ending sessions, reading or writing the server's
// files, large objects, reaching other servers, changing settings and roles, and WAL control.
var deniedFunctions = []string{
	"pg_terminate_backend", "pg_cancel_backend", "pg_reload_conf", "pg_rotate_logfile", "pg_promote",
	"pg_switch_wal", "pg_create_restore_point", "pg_backup_start", "pg_backup_stop", "pg_logical_emit_message",
	"pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file", "pg_file_write", "pg_file_rename", "pg_file_unlink",
	"lo_import", "lo_export", "lo_unlink", "lo_from_bytea", "lo_put",
	"dblink", "dblink_exec", "dblink_connect", "dblink_connect_u", "dblink_send_query",
	"set_config", "pg_advisory_lock", "pg_advisory_lock_shared",
}

// bareName returns a function's name without its schema.
func bareName(f string) string {
	_, name, ok := strings.CutLast(f, ".")
	if !ok {
		return f
	}
	return name
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
	guardsDDL bool             // the DDL guard is on, so DDL passes a gate that reports it
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
	if a := c.Allowlist; !slices.Contains([]string{"", "learn", "enforce", "off"}, a.Mode) {
		errs = append(errs, fmt.Errorf("allowlist mode %q: want learn, enforce or off", a.Mode))
	}
	if r := c.Runaway; !slices.Contains([]string{"", "log", "slow", "reject", "off"}, r.Action) || r.Watch < 0 {
		errs = append(errs, fmt.Errorf("runaway: want action log, slow, reject or off, and no negative watch"))
	}
	if l := c.LearnedTimeouts; (l.Mode != "" && l.Mode != "on" && l.Mode != "off") || l.Multiple < 0 || (l.Multiple > 0 && l.Multiple < 1) ||
		l.MinRuns < 0 || l.Floor < 0 {
		errs = append(errs, fmt.Errorf("learned_timeouts: want mode on or off, a multiple of at least 1 and no negative min_runs or floor"))
	}
	if t := c.LoginThrottle; (t.Mode != "" && t.Mode != "on" && t.Mode != "off") || t.Failures < 0 || t.Window < 0 || t.CoolOff < 0 {
		errs = append(errs, fmt.Errorf("login_throttle: want mode on or off and no negative failures, window or cool_off"))
	}
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
	if a := s.Adaptive; a != nil {
		switch {
		case s.MaxActive == 0:
			errs = append(errs, errors.New("scheduler: adaptive needs max_active, the most the limit grows to"))
		case a.Floor < 0 || a.Floor > s.MaxActive:
			errs = append(errs, errors.New("scheduler: adaptive floor must be between 0 and max_active"))
		}
		if a.Backoff < 0 || a.Backoff >= 1 {
			errs = append(errs, errors.New("scheduler: adaptive backoff must be at least 0 and under 1"))
		}
		if a.MaxSlowdown != 0 && a.MaxSlowdown <= 1 {
			errs = append(errs, errors.New("scheduler: adaptive max_slowdown must be over 1"))
		}
		if a.LockWaitShare < 0 {
			errs = append(errs, errors.New("scheduler: adaptive lock_wait_share must not be negative"))
		}
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
		case r.Check != "deny_functions" && len(r.Functions) > 0:
			errs = append(errs, fmt.Errorf("check %s: functions are allowed only in deny_functions", r.Check))
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
		if len(r.Match.Tags) > 0 && len(c.TrustedRoles) == 0 {
			errs = append(errs, fmt.Errorf("check %s: match tags narrow a rule only for trusted_roles, and none are set", r.Check))
		}
		p.costRules = p.costRules || checks[r.Check].overBy != nil
	}
	if c.TenantDefaults.Mode != "" || c.TenantDefaults.MaxConnections != 0 {
		errs = append(errs, errors.New("tenant_defaults: mode and max_connections belong to each tenant; use tenant_max_connections"))
	}
	errs = append(errs, c.TenantDefaults.validate("tenant_defaults"))
	budgeted := c.TenantDefaults.Budget != nil
	byCapacity := c.TenantDefaults.Budget != nil && c.TenantDefaults.Budget.Capacity > 0
	timed := c.TenantDefaults.limited()
	for name, t := range c.Tenants {
		if !t.Mode.valid() {
			errs = append(errs, fmt.Errorf("tenant %s: mode %q: want enforce or warn", name, t.Mode))
		}
		if t.MaxConnections < 0 {
			errs = append(errs, fmt.Errorf("tenant %s: max_connections must not be negative", name))
		}
		errs = append(errs, t.validate("tenant "+name))
		budgeted = budgeted || t.Budget != nil
		byCapacity = byCapacity || (t.Budget != nil && t.Budget.Capacity > 0)
		timed = timed || t.limited()
	}
	if byCapacity && c.Scheduler.MaxActive <= 0 {
		errs = append(errs, errors.New("budgets by capacity need scheduler max_active, the statements the server runs at once"))
	}
	if m := c.Calibration.Mode; m != "" && m != "on" && m != "off" {
		errs = append(errs, fmt.Errorf("calibration mode %q: want on or off", m))
	}
	if c.Calibration.ReturnedMB < 0 || c.Calibration.WALMB < 0 {
		errs = append(errs, errors.New("calibration returned_mb and wal_mb must not be negative"))
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
	if m := c.DDLGuard.Mode; !m.valid() && m != "off" {
		errs = append(errs, fmt.Errorf("ddl_guard mode %q: want enforce, warn or off", m))
	}
	if c.DDLGuard.LockTimeout < 0 {
		errs = append(errs, errors.New("ddl_guard lock_timeout must not be negative"))
	}
	if q := s.OverloadQueue; q.StandingAfter < 0 || q.Timeout < 0 {
		errs = append(errs, errors.New("scheduler overload_queue: standing_after and timeout must not be negative"))
	}
	if m := s.OverloadQueue.Mode; m != "" && m != "on" && m != "off" {
		errs = append(errs, fmt.Errorf("scheduler overload_queue mode %q: want on or off", m))
	}
	if s.DemoteAfter < 0 {
		errs = append(errs, errors.New("scheduler demote_after must not be negative"))
	}
	if c.ReplicationLag.Max < 0 {
		errs = append(errs, errors.New("replication_lag max must not be negative"))
	}
	if h := c.MVCCHorizon; h.MaxAge < 0 || h.MaxDeadTuples < 0 {
		errs = append(errs, errors.New("mvcc_horizon max_age and max_dead_tuples must not be negative"))
	} else if h.MaxAge == 0 && (len(h.Watch) > 0 || h.MaxDeadTuples > 0) {
		errs = append(errs, errors.New("mvcc_horizon: watch and max_dead_tuples need max_age"))
	}
	for _, name := range c.MVCCHorizon.Watch {
		if schema, table, ok := strings.Cut(name, "."); !ok || schema == "" || table == "" {
			errs = append(errs, fmt.Errorf("mvcc_horizon watch %q: want schema.table", name))
		}
	}
	if b := s.BlockerPays; b != "" && b != "on" && b != "off" {
		errs = append(errs, fmt.Errorf("scheduler blocker_pays %q: want on or off", b))
	}
	p.guardsDDL = c.DDLGuard.Mode != "off"
	slots := s.MaxActive > 0 || s.SlowLane.MaxActive > 0
	// Fair shares of slots go by cost too, so limited slots need plans as budgets do.
	p.needsCost = p.costRules || budgeted || slots
	// A lag hold and a horizon cap act at the slot a statement takes, so every statement must ask for one.
	p.gated = budgeted || timed || slots || c.ReplicationLag.Max > 0 || c.MVCCHorizon.MaxAge > 0 || c.LearnedTimeouts.Mode == "on"
	return errors.Join(errs...)
}

// validate checks a tenant's budget and timeouts.
// limited reports whether t sets a timeout or cap, which only a gate can apply.
func (t Tenant) limited() bool {
	return t.StatementTimeout > 0 || t.IdleInTransactionTimeout > 0 || t.TransactionTimeout > 0 || t.MaxRows > 0 || t.MaxBytes > 0
}

func (t Tenant) validate(name string) error {
	var errs []error
	if t.MaxRows < 0 || t.MaxBytes < 0 {
		errs = append(errs, fmt.Errorf("%s: max_rows and max_bytes must not be negative", name))
	}
	if t.StatementTimeout < 0 || t.IdleInTransactionTimeout < 0 || t.TransactionTimeout < 0 {
		errs = append(errs, fmt.Errorf("%s: statement_timeout, idle_in_transaction_timeout and transaction_timeout must not be negative", name))
	}
	if _, ok := priorities[t.Priority]; t.Priority != "" && !ok {
		errs = append(errs, fmt.Errorf("%s: priority %q: want critical, normal or best_effort", name, t.Priority))
	}
	if b := t.Budget; b != nil {
		if b.Rate < 0 || b.Burst < 0 || b.Share < 0 || b.MinCharge < 0 {
			errs = append(errs, fmt.Errorf("%s: budget rate, burst, share and min_charge must not be negative", name))
		}
		if b.Burst > 0 && b.Rate == 0 && b.Capacity == 0 {
			errs = append(errs, fmt.Errorf("%s: a budget's burst needs a rate or capacity", name))
		}
		if b.Capacity < 0 || b.Capacity > 1 || (b.Capacity > 0 && b.Rate > 0) {
			errs = append(errs, fmt.Errorf("%s: a budget's capacity is a share from 0 to 1, given in place of a rate", name))
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

// DDLGuard returns the DDL guard's settings, with its defaults filled in.
func (p *Policy) DDLGuard() DDLGuard {
	g := p.cfg.DDLGuard
	g.Mode = cmp.Or(g.Mode, Enforce)
	g.LockTimeout = cmp.Or(g.LockTimeout, Duration(DefaultDDLLockTimeout))
	return g
}

// ReplicationLag returns the most a standby may lag before best-effort statements are held back; 0 means lag isn't watched.
func (p *Policy) ReplicationLag() time.Duration { return time.Duration(p.cfg.ReplicationLag.Max) }

// Horizon returns how the MVCC horizon is watched, with its defaults filled in; a MaxAge of 0 means it isn't.
func (p *Policy) Horizon() Horizon {
	h := p.cfg.MVCCHorizon
	h.MaxDeadTuples = cmp.Or(h.MaxDeadTuples, DefaultMaxDeadTuples)
	return h
}

// Watched returns the tables whose dead tuples the MVCC horizon check reads, or nil.
func (p *Policy) Watched() []plan.Table {
	var tables []plan.Table
	for _, name := range p.cfg.MVCCHorizon.Watch {
		schema, table, _ := strings.Cut(name, ".")
		tables = append(tables, plan.Table{Schema: schema, Name: table})
	}
	return tables
}

// BlockerPays reports whether tenants are charged for the time others wait on their locks.
func (p *Policy) BlockerPays() bool { return p.cfg.Scheduler.BlockerPays != "off" }

// TenantMode returns whether a tenant's statements are held to the policy or only logged.
func (p *Policy) TenantMode(tenant string) Mode { return cmp.Or(p.cfg.Tenants[tenant].Mode, Enforce) }

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
	cfg.DemoteAfter = time.Duration(s.DemoteAfter)
	if q := s.OverloadQueue; q.Mode != "off" {
		cfg.Fast.StandingAfter = cmp.Or(time.Duration(q.StandingAfter), DefaultStandingAfter)
		cfg.Fast.StandingTimeout = cmp.Or(time.Duration(q.Timeout), DefaultStandingTimeout)
	}
	if a := s.Adaptive; a != nil {
		cfg.Controller = sched.AIMD{Floor: a.Floor, Backoff: a.Backoff, MaxSlowdown: a.MaxSlowdown, LockWaitShare: a.LockWaitShare}
	}
	return cfg
}

func (b *Budget) sched() sched.Budget {
	if b == nil {
		return sched.Budget{}
	}
	return sched.Budget{Rate: b.Rate, Burst: b.Burst, Share: b.Share, MinCharge: b.MinCharge, WhenOver: sched.Action(b.WhenOver),
		Capacity: b.Capacity}
}

// tuning returns how the plan history judges.
func (p *Policy) tuning() plan.Tuning {
	return plan.Tuning{Credibility: p.cfg.Calibration.Credibility, Quarantine: time.Duration(p.cfg.PlanFlips.Quarantine)}
}

// tenant returns a tenant's settings, with tenant_defaults' budget and timeouts where it sets none.
func (p *Policy) tenant(name string) Tenant {
	t, d := p.cfg.Tenants[name], p.cfg.TenantDefaults
	t.Budget = cmp.Or(t.Budget, d.Budget)
	t.Priority = cmp.Or(t.Priority, d.Priority)
	t.StatementTimeout = cmp.Or(t.StatementTimeout, d.StatementTimeout)
	t.IdleInTransactionTimeout = cmp.Or(t.IdleInTransactionTimeout, d.IdleInTransactionTimeout)
	t.TransactionTimeout = cmp.Or(t.TransactionTimeout, d.TransactionTimeout)
	t.MaxRows, t.MaxBytes = cmp.Or(t.MaxRows, d.MaxRows), cmp.Or(t.MaxBytes, d.MaxBytes)
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
	Backend   Backend          // told what the session's server connection runs; nil tells no one
	// WAL gives the WAL a role's statement writes per call in a database, from pg_stat_statements; nil charges writes no WAL.
	WAL func(database, role, fingerprint string) (bytes float64, ok bool)
	// P99 gives the p99 of a statement's timed runs by a role and tenant in a database, and how many there were; nil learns no timeouts.
	P99 func(database, role, tenant, fingerprint string) (time.Duration, int64)
	// Runaways is the runaway watch list, shared by every session; nil watches nothing.
	Runaways *Watch
	// Flipped is told of each new plan flip, for the anomalies it may explain; nil tells no one.
	Flipped func(database, fingerprint string)
	// Kills are the tenants and statements an operator has blocked for a while, shared by every session; nil blocks nothing.
	Kills *Kills
	// Allowlist is what each role's statements are learned to be, shared by every session; nil learns and enforces nothing.
	Allowlist *Allowlist
}

// Backend learns what one session's server connection runs, for checks that look at the whole server, such as the DDL guard.
type Backend interface {
	// Running says the connection now runs a statement of tenant, DDL or not, or has finished it (ddl false).
	Running(tenant string, ddl bool)
	// Blocking returns a channel closed while others wait on locks the connection holds.
	Blocking() <-chan struct{}
}

// Checker checks the statements of one session; only the session's own goroutine uses it.
type Checker struct {
	Env Env

	policy        func() *Policy
	role          string
	log           *slog.Logger
	warnedTag     bool          // the role sent a tenant tag it isn't trusted to send, which was logged once
	clientTimeout time.Duration // statement_timeout as the client set it at login; 0 when it set none
	roleChanged   bool          // the session may run as another role than it logged in as, so its plans are its own and never cached
}

// subject is who a statement runs for and where it comes from, as rules match it.
type subject struct {
	role, tenant, app string
	client            netip.Addr
	tags              map[string]string
	trusted           bool          // the role is trusted to tag its statements
	wait              time.Duration // how long the client waits for the statement from when it is sent to run; 0 when unknown
}

// priority returns the priority of who's statement: its tenant's, or its tag's when the role is trusted or the tag lowers it.
func (p *Policy) priority(who subject) sched.Priority {
	prio := priorities[p.tenant(who.tenant).Priority]
	// Anyone may put their own statements behind others, but only a trusted role may put them ahead.
	if tag, ok := priorities[who.tags[priorityTag]]; ok && (who.trusted || tag < prio) {
		prio = tag
	}
	return prio
}

// Admin reports whether role may use the admin console, besides superusers.
func (p *Policy) Admin(role string) bool { return slices.Contains(p.cfg.AdminRoles, role) }

// trusted reports whether role's tags can be believed: they name its statements' tenant and narrow rules.
func (p *Policy) trusted(role string) bool { return slices.Contains(p.cfg.TrustedRoles, role) }

// Check returns the error to send instead of running sql, or nil, and the gate it passes just before it executes, if any.
func (c *Checker) Check(sql string, set session.Settings) (*pgproto3.ErrorResponse, session.Gate) {
	rej, gate := c.check(sql, set)
	if rej != nil || c.Env.Kills == nil {
		return rej, gate
	}
	// A prepared statement runs again without being checked, so each run looks at the kills made since.
	return nil, func(ctx context.Context, e session.Explain, running bool) session.Admission {
		if rej := c.killedNow(c.policy(), sql); rej != nil {
			return session.Admission{Reject: rej}
		}
		if gate == nil {
			return session.Admission{}
		}
		return gate(ctx, e, running)
	}
}

// killedNow returns the error for sql when its tenant or the statement is killed, or nil.
func (c *Checker) killedNow(p *Policy, sql string) *pgproto3.ErrorResponse {
	k := c.Env.Kills
	if k == nil || k.empty() {
		return nil
	}
	now := time.Now()
	tenant := c.tenant(p, sqlparse.Tags(sql))
	if left, ok := k.killed(KillTenant, tenant, now); ok {
		c.log.Warn("rejected statement", "rule", "kill", "tenant", tenant)
		return killed("tenant", left)
	}
	if left, ok := k.killed(KillFingerprint, sqlparse.Fingerprint(sql), now); ok {
		c.log.Warn("rejected statement", "rule", "kill", "tenant", tenant, "query", sqlparse.Normalize(sql))
		return killed("statement", left)
	}
	return nil
}

// check is Check without the kills made after it.
func (c *Checker) check(sql string, set session.Settings) (*pgproto3.ErrorResponse, session.Gate) {
	p := c.policy()
	if l := p.cfg.Allowlist; l.applies(c.role) && c.Env.Allowlist != nil {
		fp := sqlparse.Fingerprint(sql)
		switch {
		case l.Mode == "learn" && fp != "" && !c.Env.Allowlist.allowed(c.role, fp):
			if c.Env.Allowlist.learn(c.role, fp, sqlparse.Normalize(sql)) {
				c.log.Info("learned a statement for the allowlist", "query", sqlparse.Normalize(sql))
			}
		case l.Mode == "enforce" && !c.Env.Allowlist.allowed(c.role, fp):
			c.log.Warn("rejected statement", "rule", "allowlist", "query", sqlparse.Normalize(sql))
			return rejection("42501", "queryguard: statement is not on the role's allowlist",
				"Only statements learned for this role may run.", "Learn it first with the allowlist in learn mode."), nil
		}
	}
	if rej := c.killedNow(p, sql); rej != nil {
		return rej, nil
	}
	// Without a Backend to tell, nothing needs DDL found, so a policy with nothing else to check needn't parse the statement.
	guardsDDL := p.guardsDDL && c.Env.Backend != nil
	if len(p.cfg.Rules) == 0 && !p.gated && !guardsDDL {
		// Nothing is parsed, but a policy loaded later must still know the role may have changed.
		if mayChangeRole(sql) {
			c.changedRole()
		}
		return nil, nil
	}
	tags := sqlparse.Tags(sql)
	who := subject{role: c.role, tenant: c.tenant(p, tags), app: set.ApplicationName, client: c.Env.Client, tags: tags, trusted: p.trusted(c.role),
		wait: c.wait(tags)}
	warn := p.cfg.Tenants[who.tenant].Mode == Warn

	reason := misread(sql, set)
	var q sqlparse.Query
	if reason == "" {
		var err error
		if q, err = sqlparse.Analyze(sql); err != nil {
			reason = "The parser cannot read it: " + err.Error()
		}
	}
	if q.ChangesTimeout {
		// The new value is known only once the statement runs, if it does, so the client's wait is no longer known.
		c.clientTimeout = 0
	}
	if q.ChangesRole || reason != "" {
		c.changedRole()
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
	if !p.gated && !(p.costRules && (q.Explainable || q.DDL || q.Analyzes)) && !(guardsDDL && q.DDL) {
		return nil, nil
	}
	return nil, c.gate(p, sql, q, who)
}

// deadlineTag is the sqlcommenter key giving how long, from when it is sent to run, a statement's client waits for it.
const deadlineTag = "deadline"

// wait returns how long the client waits for a statement with tags, queue included: the shorter of its login's
// statement_timeout and its deadline tag; 0 when it gave neither.
func (c *Checker) wait(tags map[string]string) time.Duration {
	wait := c.clientTimeout
	if d, ok := pgDuration(tags[deadlineTag]); ok && d > 0 && (wait == 0 || d < wait) {
		wait = d
	}
	return wait
}

// pgUnits are the units Postgres takes for time settings; a number alone is in milliseconds.
var pgUnits = map[string]time.Duration{"": time.Millisecond, "us": time.Microsecond, "ms": time.Millisecond, "s": time.Second,
	"min": time.Minute, "h": time.Hour, "d": 24 * time.Hour}

// pgDuration reads a time setting such as statement_timeout as Postgres does: "500", "1.5s" or "2 min".
func pgDuration(v string) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	i := strings.IndexFunc(v, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	if i < 0 {
		i = len(v)
	}
	n, err := strconv.ParseFloat(v[:i], 64)
	unit, ok := pgUnits[strings.TrimSpace(v[i:])]
	if err != nil || !ok || n < 0 {
		return 0, false
	}
	return time.Duration(n * float64(unit)), true
}

// tenant returns who a statement runs for: the tenant its tag names when the role is trusted to name one, else the role.
func (c *Checker) tenant(p *Policy, tags map[string]string) string {
	name := p.taggedTenant(tags)
	switch {
	case name == "":
		return c.role
	case p.trusted(c.role):
		return name
	}
	if !c.warnedTag {
		c.warnedTag = true
		c.log.Warn("ignored a tenant tag from a role not trusted to name one", "tag", name)
	}
	return c.role
}

// taggedTenant returns the tenant tags name, trusted or not; "" when they name none.
func (p *Policy) taggedTenant(tags map[string]string) string {
	return tags[cmp.Or(p.cfg.TenantTag, defaultTenantTag)]
}

// TenantOf returns the tenant role's statement sql runs for: its tag's when role is trusted to send one, else role.
func (p *Policy) TenantOf(role, sql string) string {
	if name := p.taggedTenant(sqlparse.Tags(sql)); name != "" && p.trusted(role) {
		return name
	}
	return role
}

// gate admits sql as admit does, and tells the Backend what runs.
func (c *Checker) gate(p *Policy, sql string, q sqlparse.Query, who subject) session.Gate {
	admit := c.admit(p, sql, q, who)
	return func(ctx context.Context, e session.Explain, running bool) session.Admission {
		a := admit(ctx, e, running)
		if b := c.Env.Backend; b != nil && a.Reject == nil {
			b.Running(who.tenant, q.DDL)
			ran := a.Ran
			a.Ran = func(took time.Duration, finished bool) {
				if ran != nil {
					ran(took, finished)
				}
				b.Running(who.tenant, false)
			}
			idle := a.Idle
			a.Idle = func() {
				if idle != nil {
					idle()
				}
				b.Running(who.tenant, false)
			}
		}
		return a
	}
}

// admit admits sql when it is about to execute: it waits for the tenant's budget, judges the plan, and takes a slot.
func (c *Checker) admit(p *Policy, sql string, q sqlparse.Query, who subject) session.Gate {
	return func(ctx context.Context, e session.Explain, running bool) session.Admission {
		t := p.tenant(who.tenant)
		warn := t.Mode == Warn
		a := session.Admission{Timeout: time.Duration(t.StatementTimeout), IdleInTransaction: time.Duration(t.IdleInTransactionTimeout),
			TransactionTimeout: time.Duration(t.TransactionTimeout)}
		if q.TransactionControl {
			// A slot may be held by a statement waiting on this transaction's locks, which only its end frees.
			return a
		}
		if q.ReadOnly && !warn {
			a.MaxRows, a.MaxBytes = t.MaxRows, t.MaxBytes
		}
		var fingerprint string
		runaway, cooled := p.cfg.Runaway, false
		if w := c.Env.Runaways; w != nil && runaway.Action != "off" {
			if !w.empty() {
				fingerprint = sqlparse.Fingerprint(sql)
				if left, first, ok := w.watched(c.Env.Database, fingerprint, time.Now()); ok {
					switch {
					case runaway.Action == "reject" && !warn:
						c.log.Warn("rejected statement", "rule", "runaway", "tenant", who.tenant, "query", sqlparse.Normalize(sql))
						return session.Admission{Reject: onWatch(left)}
					case runaway.Action == "slow":
						cooled = true
					case first:
						c.log.Warn("runaway statement runs again", "tenant", who.tenant, "query", sqlparse.Normalize(sql), "watched_for", left.Round(time.Second))
					}
				}
			}
			a.Broke = func(i session.Interruption) {
				// A statement cancelled for its timeout or a cap is a runaway; one cancelled for a lock, by the DDL guard, isn't.
				if i.Code != "57014" && i.Code != "54000" {
					return
				}
				fp := cmp.Or(fingerprint, sqlparse.Fingerprint(sql))
				d := cmp.Or(time.Duration(runaway.Watch), DefaultRunawayWatch)
				w.add(c.Env.Database, fp, sqlparse.Normalize(sql), i.Code, d, time.Now())
				c.log.Warn("statement put on the runaway watch list", "tenant", who.tenant, "query", sqlparse.Normalize(sql), "code", i.Code,
					"action", cmp.Or(runaway.Action, "log"), "for", d)
			}
		}
		s := c.Env.Scheduler
		if s != nil && p.cfg.Calibration.Mode != "off" {
			perMB := cmp.Or(p.cfg.Calibration.ReturnedMB, DefaultReturnedMB)
			a.Returned = func(_, bytes int64) { s.Surcharge(who.tenant, float64(bytes)/(1<<20)*perMB) }
		}
		// A prepared statement passes its gate at every execution, and the client's wait starts at each.
		var deadline time.Time
		if who.wait > 0 && !warn {
			deadline = time.Now().Add(who.wait)
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, deadline)
			defer cancel()
		}
		// Others waiting on the session's locks wait until its next statement, likely its COMMIT, runs, so it waits for nothing.
		ctx, holds := c.holdingLocks(ctx)
		defer holds.stop(nil)

		// The budget is looked at before EXPLAIN, the dearest step, and spent once the cost is known.
		if s != nil && !warn {
			if _, err := s.Reserve(ctx, who.tenant); err != nil && !holds.locks() {
				return c.refuse(err, who, "budget", overBudget(s, who.tenant))
			}
		}

		var cost float64
		var flipped bool
		var usual time.Duration
		// A session that can't explain the statement here passes no Run, and it is judged without a plan.
		if q.Explainable && e.Run != nil && (p.costRules || (s != nil && p.needsCost)) {
			fingerprint = sqlparse.Fingerprint(sql)
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
				cost, flipped, usual, a.Ran = c.learn(p, sql, fingerprint, who, warn, pl)
			}
		}
		if !deadline.IsZero() && usual > 0 {
			// It must start by when it can still end in its usual time.
			start := deadline.Add(-usual)
			if !time.Now().Before(start) {
				return c.refuse(context.DeadlineExceeded, who, "deadline", pastDeadline())
			}
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, start)
			defer cancel()
		}
		if l := p.cfg.LearnedTimeouts; l.Mode == "on" && c.Env.P99 != nil {
			if fingerprint == "" {
				fingerprint = sqlparse.Fingerprint(sql)
			}
			if learned, ok := l.timeout(c.Env.P99(c.Env.Database, c.role, who.tenant, fingerprint)); ok && (a.Timeout == 0 || learned < a.Timeout) {
				a.Timeout = learned
			}
		}
		// EXPLAIN leaves out triggers, foreign key checks and index upkeep, which the WAL a write usually writes shows.
		if !q.ReadOnly && c.Env.WAL != nil && s != nil && p.cfg.Calibration.Mode != "off" {
			if fingerprint == "" {
				fingerprint = sqlparse.Fingerprint(sql)
			}
			if w, ok := c.Env.WAL(c.Env.Database, c.role, fingerprint); ok {
				cost += w / (1 << 20) * cmp.Or(p.cfg.Calibration.WALMB, DefaultWALMB)
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
			switch {
			case err != nil && holds.locks():
				s.Charge(who.tenant, cost)
			case err != nil:
				return c.refuse(err, who, "budget", overBudget(s, who.tenant))
			default:
				lane = l
			}
		}
		if flipped || cooled {
			lane = sched.Slow
		}
		if !running {
			release, err := s.Acquire(ctx, who.tenant, lane, p.priority(who))
			switch {
			case err != nil && holds.locks():
				c.log.Info("let in a statement of a session others wait on", "tenant", who.tenant, "lane", lane)
				a.Release = s.Force(who.tenant, lane)
			case err != nil && warn:
				c.log.Warn("would reject statement", "rule", "busy", "tenant", who.tenant, "lane", lane)
			case errors.Is(err, sched.ErrShed):
				s.Refund(who.tenant, cost)
				c.log.Warn("rejected statement", "rule", "overload", "tenant", who.tenant, "err", err)
				return session.Admission{Reject: shed()}
			case errors.Is(err, sched.ErrHeld):
				s.Refund(who.tenant, cost)
				c.log.Warn("rejected statement", "rule", "held", "tenant", who.tenant, "err", err)
				return session.Admission{Reject: heldBack()}
			case err != nil:
				s.Refund(who.tenant, cost)
				return c.refuse(err, who, "busy", busy(p, lane))
			default:
				a.Release = release
			}
		}
		return a
	}
}

// errHoldsLocks ends the waits of a statement whose session holds locks others wait on.
var errHoldsLocks = errors.New("others wait on the session's locks")

// holding watches whether others wait on the session's locks while one of its statements waits to be admitted.
type holding struct {
	ctx  context.Context
	stop context.CancelCauseFunc
}

// locks reports whether others came to wait on the session's locks.
func (h holding) locks() bool { return errors.Is(context.Cause(h.ctx), errHoldsLocks) }

// holdingLocks returns a context that ends, with errHoldsLocks as its cause, once the Backend says others wait on the session's
// locks; call stop when the statement's waits are over.
func (c *Checker) holdingLocks(ctx context.Context) (context.Context, holding) {
	ctx, stop := context.WithCancelCause(ctx)
	h := holding{ctx: ctx, stop: stop}
	if b := c.Env.Backend; b != nil {
		blocking, done := b.Blocking(), ctx.Done()
		go func() {
			select {
			case <-blocking:
				stop(errHoldsLocks)
			case <-done:
			}
		}()
	}
	return ctx, h
}

// refuse logs and returns the rejection for a statement whose wait ended with err: rej, unless it was its deadline that ended it.
func (c *Checker) refuse(err error, who subject, rule string, rej *pgproto3.ErrorResponse) session.Admission {
	// Only a statement's own deadline puts one on the context a gate waits with.
	if errors.Is(err, context.DeadlineExceeded) {
		rule, rej = "deadline", pastDeadline()
	}
	c.log.Warn("rejected statement", "rule", rule, "tenant", who.tenant, "err", err)
	return session.Admission{Reject: rej}
}

// plan gets sql's plan, cached or explained by the session, and judges it by the cost rules; ok is false when Postgres refused sql.
func (c *Checker) plan(p *Policy, sql, fingerprint string, who subject, warn bool, e session.Explain) (_ plan.Plan, rej *pgproto3.ErrorResponse, ok bool) {
	// A generic plan holds for any values.
	key := c.statementKey(fingerprint) + "\x00" + strconv.FormatBool(e.Generic)
	if !e.Generic && p.enforcesCost(who, warn) {
		// Values change the plan, so a cheap plan cached for one value must not pass another; logging and budgets can share one.
		h := sha256.Sum256([]byte(sql))
		key += "\x00" + string(h[:]) + e.Values
	}
	explain := func() (plan.Plan, error) {
		out, err := e.Run()
		if err != nil {
			return plan.Plan{}, err
		}
		return plan.Parse(out)
	}
	var pl plan.Plan
	var err error
	if c.roleChanged {
		// Row-level security can plan the same text differently for each role the session switches to.
		pl, err = explain()
	} else {
		pl, err = c.plans().Get(key, explain)
	}
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

// enforcesCost reports whether a cost rule that blocks applies to who.
func (p *Policy) enforcesCost(who subject, warn bool) bool {
	if warn {
		return false
	}
	for i, r := range p.cfg.Rules {
		if checks[r.Check].overBy != nil && r.Mode != Warn && p.matches(i, who) {
			return true
		}
	}
	return false
}

// learn looks pl up in its statement's history; it returns the cost to charge, whether to run it in the slow lane, and what to record once it ran.
func (c *Checker) learn(p *Policy, sql, fingerprint string, who subject, warn bool, pl plan.Plan) (cost float64, slow bool, usual time.Duration, ran func(time.Duration, bool)) {
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
		if v.First && c.Env.Flipped != nil {
			c.Env.Flipped(c.Env.Database, fingerprint)
		}
		if v.First {
			c.log.Warn("plan flip", append([]any{"rule", "plan_flips", "tenant", who.tenant, "fingerprint", fingerprint,
				"query", sqlparse.Normalize(sql), "why", v.Flip, "cost", pl.Cost, "slow_lane", slow}, c.stale(pl)...)...)
		}
	}
	return cost, slow, v.Usual, func(took time.Duration, finished bool) {
		if s := c.Env.Scheduler; s != nil && took > 0 {
			if finished && v.Usual > 0 {
				s.Finished(float64(took) / float64(v.Usual))
			}
			// The plan's cost was a guess; what the statement took, failed or not, is what it cost.
			if actual, ok := history.CostOf(took); ok && p.cfg.Calibration.Mode != "off" {
				s.TrueUp(who.tenant, cost, actual)
			}
		}
		if !history.Ran(who.tenant, key, pl, took, finished, tune) {
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
	role := c.role
	if c.roleChanged {
		// The role it runs as is not known, so its history is kept apart from every other session's.
		role += fmt.Sprintf("\x00%p", c)
	}
	return strings.Join([]string{c.Env.Database, role, fingerprint}, "\x00")
}

// changedRole notes that the session may now run as another role than it logged in as.
func (c *Checker) changedRole() {
	if !c.roleChanged {
		c.log.Info("session may have changed its role; its plans are no longer cached or shared", "role", c.role)
	}
	c.roleChanged = true
}

// mayChangeRole is a quick look, without parsing, for anything that could change a statement's role.
func mayChangeRole(sql string) bool {
	sql = strings.ToLower(sql)
	return strings.Contains(sql, "role") || strings.Contains(sql, "authorization") || strings.Contains(sql, "set_config") ||
		strings.Contains(sql, "pg_settings")
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
	who := subject{role: c.role, tenant: c.role, client: c.Env.Client, trusted: p.trusted(c.role)}
	warn := p.cfg.Tenants[c.role].Mode == Warn
	all := maps.Collect(settings)
	who.app = all["application_name"]
	if d, ok := pgDuration(all["statement_timeout"]); ok {
		c.clientTimeout = d
	}
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
	// An untrusted client could drop or change a tag to leave a rule, so tags narrow rules only for trusted roles.
	for k, v := range m.Tags {
		if who.trusted && who.tags[k] != v {
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

// overBudget is the error for a statement whose tenant's budget is spent and owes nothing again after retry.
func overBudget(s *sched.Scheduler, tenant string) *pgproto3.ErrorResponse {
	detail, retry := "The tenant's cost budget is spent.", s.RetryAfter(tenant)
	switch rate := s.Rate(tenant); {
	case rate > 0:
		detail = fmt.Sprintf("The tenant's cost budget is spent; it refills at %.0f cost units a second.", rate)
	case rate < 0:
		detail, retry = "This instance has no share of the tenant's fleet-wide cost budget yet.", retryBase
	}
	return rejection("53000", "queryguard: tenant is over its cost budget", detail, retryHint(retry)+", or run fewer or cheaper statements.")
}

// retryBase is how long a client turned away for want of a slot is told to wait before trying again.
const retryBase = time.Second

// retryHint tells the client to retry after d plus up to half again, so clients turned away together don't all come back at once.
func retryHint(d time.Duration) string {
	d = max(d, 100*time.Millisecond)
	d += rand.N(d/2 + 1)
	return fmt.Sprintf("Retry in about %s", d.Round(100*time.Millisecond))
}

// busy is the error for a statement that found no free slot in time.
func busy(p *Policy, lane sched.LaneID) *pgproto3.ErrorResponse {
	wait := cmp.Or(time.Duration(p.cfg.Scheduler.QueueTimeout), sched.DefaultQueueTimeout)
	if lane == sched.Slow {
		wait = cmp.Or(time.Duration(p.cfg.Scheduler.SlowLane.QueueTimeout), sched.DefaultSlowQueueTimeout)
	}
	return rejection("53000", "queryguard: too busy to run the statement",
		fmt.Sprintf("No slot in the %s lane came free within %s.", lane, wait), retryHint(retryBase)+".")
}

// shed is the error for a best-effort statement turned away while the server is overloaded.
func shed() *pgproto3.ErrorResponse {
	return rejection("53000", "queryguard: server overloaded; best-effort statements are shed",
		"The server is overloaded, so statements of best_effort priority run only when a slot is free.", retryHint(retryBase)+".")
}

// pastDeadline is the error for a statement that can no longer end before its client's statement_timeout or deadline tag.
func pastDeadline() *pgproto3.ErrorResponse {
	return rejection("57014", "queryguard: canceling statement that can't end before its deadline",
		"Waiting for its turn, then running for as long as it usually does, would take it past the client's statement_timeout or deadline tag.",
		"Retry later, or allow it more time.")
}

// killed is the error for a statement of a tenant, or a statement, an operator has blocked for left more.
func killed(what string, left time.Duration) *pgproto3.ErrorResponse {
	return rejection("53000", "queryguard: this "+what+" is blocked by an operator",
		"An operator turned on QueryGuard's kill switch for it.", retryHint(left)+", or ask the operator.")
}

// onWatch is the error for a statement on the runaway watch list for left more.
func onWatch(left time.Duration) *pgproto3.ErrorResponse {
	return rejection("53000", "queryguard: statement is on the runaway watch list",
		"A recent run of it was cancelled for breaking its timeout or a row cap, so it is turned away while it is watched.",
		retryHint(left)+", or make it cheaper.")
}

// heldBack is the error for a best-effort statement held back past its queue timeout, as while a standby lags.
func heldBack() *pgproto3.ErrorResponse {
	return rejection("53000", "queryguard: best-effort statements are held back",
		"Statements of best_effort priority wait while a standby lags too far behind.", retryHint(retryBase)+".")
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
