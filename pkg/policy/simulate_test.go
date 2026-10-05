package policy

import (
	"testing"
	"time"

	"github.com/Avik-creator/queryguard/pkg/stats"
)

func TestSimulateReplaysRulesAndBudgets(t *testing.T) {
	p := mustParse(t, `{"rules": [{"check": "deny_ddl", "match": {"roles": ["app"]}}],
		"tenants": {"app": {"budget": {"rate": 100, "burst": 100, "when_over": "reject"}},
			"batch": {"budget": {"rate": 10, "burst": 10}}}}`)
	at := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	recs := []stats.Record{
		{At: at, Database: "shop", Role: "app", Tenant: "app", Query: "drop table orders"},
		{At: at, Database: "shop", Role: "app", Tenant: "app", Query: "select * from orders where id = $1", Units: 60},
		{At: at, Database: "shop", Role: "app", Tenant: "app", Query: "select * from orders where id = $1", Units: 60},
		// Too little has refilled by now for a third.
		{At: at.Add(100 * time.Millisecond), Database: "shop", Role: "app", Tenant: "app", Query: "select * from orders where id = $1", Units: 60, Rejected: true},
		{At: at, Database: "shop", Role: "batch", Tenant: "batch", Query: "select count(*) from orders", Units: 30},
		{At: at, Database: "shop", Role: "batch", Tenant: "batch", Query: "select count(*) from orders", Units: 30},
	}

	r := Simulate(p, recs)

	if r.Statements != 6 || !r.From.Equal(at) {
		t.Errorf("replayed %d from %v; want 6 from %v", r.Statements, r.From, at)
	}
	if got := r.Rules["deny_ddl"]; got == nil || got.Count != 1 || got.Examples[0] != "drop table orders" {
		t.Errorf("deny_ddl %+v; want the drop", got)
	}
	if b := r.Budgets["app"]; b == nil || b.Rejected != 1 {
		t.Errorf("app budget %+v; want one rejected", b)
	}
	// Batch queues: its second statement waits for the 20 units it owes at 10 a second.
	if b := r.Budgets["batch"]; b == nil || b.Waited != 1 || b.Wait != 2*time.Second {
		t.Errorf("batch budget %+v; want one wait of 2s", b)
	}
	// The drop was not refused when it ran, and the third select was already refused.
	if r.NewlyRejected != 1 || r.NoLongerRejected != 0 {
		t.Errorf("newly rejected %d, no longer %d; want 1 and 0", r.NewlyRejected, r.NoLongerRejected)
	}
}

func TestSimulateSaysWhatItCannotReplay(t *testing.T) {
	p := mustParse(t, `{"rules": [{"check": "max_cost", "cost": 1000}], "scheduler": {"max_active": 4},
		"tenant_defaults": {"budget": {"capacity": 0.5}}}`)

	r := Simulate(p, nil)

	if len(r.NotSimulated) < 2 {
		t.Errorf("not simulated %q; want cost rules and capacity budgets named", r.NotSimulated)
	}
}
