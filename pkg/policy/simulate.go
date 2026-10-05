package policy

import (
	"cmp"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/Avik-creator/queryguard/pkg/session"
	"github.com/Avik-creator/queryguard/pkg/stats"
)

// examplesKept is how many statements a simulated rule keeps as examples.
const examplesKept = 3

// Simulation is what a policy would have done to recorded traffic.
type Simulation struct {
	Statements       int
	From, To         time.Time
	Rules            map[string]*SimulatedRule   // by rule, or allowlist or unchecked
	Budgets          map[string]*SimulatedBudget // by tenant
	NewlyRejected    int                         // statements it would refuse that ran when recorded
	NoLongerRejected int                         // statements refused when recorded that it would run
	NotSimulated     []string                    // what of the policy replaying can't show
}

// SimulatedRule is how often a rule would have refused a statement, with a few of them.
type SimulatedRule struct {
	Count    int
	Examples []string
}

// SimulatedBudget is what a tenant's budget would have done.
type SimulatedBudget struct {
	Rejected, Waited, Slowed int
	Wait                     time.Duration // the waits added up
}

// bucket is a tenant's budget in the replay's time.
type bucket struct {
	tokens float64
	at     time.Time
}

// readingAsRecorded are the settings recorded statements are read under: their text is Postgres's normalized form, in UTF-8.
var readingAsRecorded = session.Settings{StandardConformingStrings: "on", ClientEncoding: "UTF8"}

// Simulate replays recorded statements, in time order, against p: its rules, allowlist checks and budgets.
func Simulate(p *Policy, records []stats.Record) Simulation {
	sim := Simulation{Rules: map[string]*SimulatedRule{}, Budgets: map[string]*SimulatedBudget{}}
	if p.costRules {
		sim.NotSimulated = append(sim.NotSimulated, "cost rules (max_cost, max_scan_rows), which need each statement's plan")
	}
	if p.cfg.TenantDefaults.Budget != nil && p.cfg.TenantDefaults.Budget.Capacity > 0 ||
		slices.ContainsFunc(slices.Collect(maps.Values(p.cfg.Tenants)), func(t Tenant) bool { return t.Budget != nil && t.Budget.Capacity > 0 }) {
		sim.NotSimulated = append(sim.NotSimulated, "budgets by capacity, which follow the server's measured capacity")
	}
	if p.cfg.Scheduler.MaxActive > 0 {
		sim.NotSimulated = append(sim.NotSimulated, "slots and the queue for them, which depend on how long statements overlap")
	}

	records = slices.Clone(records)
	slices.SortStableFunc(records, func(a, b stats.Record) int { return a.At.Compare(b.At) })
	quiet := slog.New(slog.DiscardHandler)
	checkers := map[string]*Checker{}
	buckets := map[string]*bucket{}
	for _, rec := range records {
		sim.Statements++
		if sim.From.IsZero() {
			sim.From = rec.At
		}
		sim.To = rec.At
		c := checkers[rec.Database+"\x00"+rec.Role]
		if c == nil {
			c = p.Checker(rec.Role, quiet)
			c.Env = Env{Database: rec.Database}
			checkers[rec.Database+"\x00"+rec.Role] = c
		}
		refused := false
		if rej, _ := c.Check(rec.Query, readingAsRecorded); rej != nil {
			r := sim.rule(ruleName(rej.Message))
			r.Count++
			if len(r.Examples) < examplesKept && !slices.Contains(r.Examples, rec.Query) {
				r.Examples = append(r.Examples, rec.Query)
			}
			refused = true
		} else if !rec.NotRun {
			refused = sim.spend(p, buckets, rec)
		}
		switch {
		case refused && !rec.Rejected:
			sim.NewlyRejected++
		case !refused && rec.Rejected:
			sim.NoLongerRejected++
		}
	}
	return sim
}

// spend charges rec to its tenant's budget, as of when it ran, and reports whether the budget would have refused it.
func (sim *Simulation) spend(p *Policy, buckets map[string]*bucket, rec stats.Record) bool {
	b := p.tenant(rec.Tenant).Budget
	if b == nil || b.Rate <= 0 {
		return false
	}
	burst := cmp.Or(b.Burst, b.Rate)
	t := buckets[rec.Tenant]
	if t == nil {
		t = &bucket{tokens: burst, at: rec.At}
		buckets[rec.Tenant] = t
	}
	t.tokens = min(burst, t.tokens+b.Rate*rec.At.Sub(t.at).Seconds())
	t.at = rec.At
	s := sim.Budgets[rec.Tenant]
	if s == nil {
		s = &SimulatedBudget{}
		sim.Budgets[rec.Tenant] = s
	}
	if t.tokens < 0 {
		switch b.WhenOver {
		case "reject":
			s.Rejected++
			return true
		case "slow":
			s.Slowed++
		default:
			s.Waited++
			s.Wait += time.Duration(-t.tokens / b.Rate * float64(time.Second))
		}
	}
	t.tokens -= max(rec.Units, b.MinCharge)
	return false
}

func (sim *Simulation) rule(name string) *SimulatedRule {
	r := sim.Rules[name]
	if r == nil {
		r = &SimulatedRule{}
		sim.Rules[name] = r
	}
	return r
}

// ruleName names what refused a statement, from its error's message.
func ruleName(message string) string {
	if rest, ok := strings.CutPrefix(message, "queryguard: rule "); ok {
		name, _, _ := strings.Cut(rest, " ")
		return name
	}
	switch {
	case strings.Contains(message, "allowlist"):
		return "allowlist"
	case strings.Contains(message, "could not be checked"):
		return "unchecked"
	}
	return message
}
