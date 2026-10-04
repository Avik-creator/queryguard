// Package sched admits statements by their tenant's cost budget and a fair share of the server's slots.
package sched

import (
	"cmp"
	"context"
	"errors"
	"math"
	"slices"
	"sync"
	"time"
)

// Defaults used when the matching Lane field is zero.
const (
	DefaultQueueTimeout     = 5 * time.Second
	DefaultSlowQueueTimeout = 60 * time.Second
)

// usageHalfLife is how fast past use stops counting when slots are handed out.
const usageHalfLife = 10 * time.Second

// maxTenants bounds the tenants kept; past it, tenants with a full budget and no recent use are forgotten.
const maxTenants = 10_000

// Action says what happens to a statement whose tenant's budget is spent.
type Action string

const (
	Queue    Action = "queue"  // wait for the budget to refill, up to the fast lane's queue timeout
	SlowLane Action = "slow"   // run in the slow lane
	Reject   Action = "reject" // fail at once
)

// Budget is one tenant's allowance of cost units.
type Budget struct {
	Rate      float64 // units added each second; 0 means the tenant is not limited
	Burst     float64 // the most units saved up; 0 means Rate, a second's worth
	Share     float64 // the tenant's weight when slots are handed out; 0 means 1
	MinCharge float64 // the least any statement costs, so a tight loop of cheap ones still counts
	WhenOver  Action  // "" means Queue
}

// Lane is a pool of slots, each running one statement at a time.
type Lane struct {
	MaxActive    int           // statements running at once; 0 means no limit
	QueueTimeout time.Duration // the longest a statement waits for its slot or budget; 0 means the lane's default
}

// LaneID picks a lane.
type LaneID int

const (
	Fast LaneID = iota
	Slow
)

func (l LaneID) String() string {
	if l == Slow {
		return "slow"
	}
	return "fast"
}

// Config sets the lanes and the budgets.
type Config struct {
	Fast, Slow Lane
	Budgets    map[string]Budget // by tenant
	Default    Budget            // for tenants not in Budgets
}

var (
	ErrOverBudget = errors.New("the tenant's cost budget is spent")
	ErrBusy       = errors.New("no slot came free in time")
)

// Scheduler is safe for concurrent use.
type Scheduler struct {
	mu      sync.Mutex
	cfg     Config
	tenants map[string]*tenant
	lanes   [2]lane
}

// tenant is one tenant's state, brought up to date by refresh before each use.
type tenant struct {
	tokens  float64   // cost units left; below zero, what the tenant owes
	usage   float64   // cost charged, fading with usageHalfLife
	updated time.Time // when tokens and usage were last brought up to date
}

type lane struct {
	active  int
	waiters []*waiter // in arrival order
}

type waiter struct {
	tenant  string
	granted chan struct{} // closed when the waiter is given a slot
}

// New returns a Scheduler with cfg.
func New(cfg Config) *Scheduler {
	s := &Scheduler{tenants: map[string]*tenant{}}
	s.Configure(cfg)
	return s
}

// Configure replaces the lanes and budgets, keeping each tenant's balance and use, as a reloaded config does.
func (s *Scheduler) Configure(cfg Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name := range s.tenants {
		// Balances accrue at the old rate up to now, and the new burst caps them from here.
		s.refresh(name)
	}
	s.cfg = cfg
	s.grant(Fast)
	s.grant(Slow)
}

// Reserve waits until tenant owes nothing, charging nothing: the cheap check before EXPLAIN, while Spend makes the decision.
func (s *Scheduler) Reserve(ctx context.Context, tenant string) (LaneID, error) {
	return s.wait(ctx, tenant, 0, false)
}

// Spend checks and charges under one lock, so statements arriving together can't spend the same budget; when spent, Action decides.
func (s *Scheduler) Spend(ctx context.Context, tenant string, cost float64) (LaneID, error) {
	return s.wait(ctx, tenant, cost, true)
}

func (s *Scheduler) wait(ctx context.Context, tenant string, cost float64, charge bool) (LaneID, error) {
	deadline := time.Now().Add(s.queueTimeout(Fast))
	for {
		s.mu.Lock()
		b, t := s.budget(tenant), s.refresh(tenant)
		lane := Fast
		if b.Rate > 0 && t.tokens < 0 {
			switch b.WhenOver {
			case Reject:
				s.mu.Unlock()
				return 0, ErrOverBudget
			case SlowLane:
				lane = Slow
			default:
				wait := time.Duration(math.Ceil(-t.tokens / b.Rate * float64(time.Second)))
				s.mu.Unlock()
				// The wait is known in advance, so there is no point starting one that can't end in time.
				if time.Now().Add(wait).After(deadline) {
					return 0, ErrOverBudget
				}
				timer := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					timer.Stop()
					return 0, ctx.Err()
				case <-timer.C:
				}
				continue
			}
		}
		if charge {
			s.charge(tenant, b, t, cost)
		}
		s.mu.Unlock()
		return lane, nil
	}
}

// Charge takes a statement's cost, at least MinCharge, however much the tenant owes, as for a tenant in warn mode.
func (s *Scheduler) Charge(tenant string, cost float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.charge(tenant, s.budget(tenant), s.refresh(tenant), cost)
}

// charge takes cost from t; the caller holds mu.
func (s *Scheduler) charge(name string, b Budget, t *tenant, cost float64) {
	cost = max(cost, b.MinCharge)
	if b.Rate > 0 {
		t.tokens -= cost
	}
	t.usage += cost
	if len(s.tenants) > maxTenants {
		s.forgetIdle()
	}
}

// Spent reports whether tenant owes cost units, so its next statement would wait, go to the slow lane or fail.
func (s *Scheduler) Spent(tenant string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.budget(tenant).Rate > 0 && s.refresh(tenant).tokens < 0
}

// Refund gives back what Spend charged for a statement that then didn't run.
func (s *Scheduler) Refund(tenant string, cost float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, t := s.budget(tenant), s.refresh(tenant)
	cost = max(cost, b.MinCharge)
	if b.Rate > 0 {
		t.tokens = min(b.Burst, t.tokens+cost)
	}
	t.usage = max(0, t.usage-cost)
}

// Acquire waits for a slot in lane, handed to the least-served tenant first, and returns the func that frees it.
func (s *Scheduler) Acquire(ctx context.Context, tenant string, id LaneID) (release func(), err error) {
	s.mu.Lock()
	l, limit := &s.lanes[id], s.lane(id).MaxActive
	if limit == 0 || (l.active < limit && len(l.waiters) == 0) {
		l.active++
		s.mu.Unlock()
		return s.releaser(id), nil
	}
	w := &waiter{tenant: tenant, granted: make(chan struct{})}
	l.waiters = append(l.waiters, w)
	s.mu.Unlock()

	timer := time.NewTimer(s.queueTimeout(id))
	defer timer.Stop()
	select {
	case <-w.granted:
		return s.releaser(id), nil
	case <-ctx.Done():
		err = ctx.Err()
	case <-timer.C:
		err = ErrBusy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if i := slices.Index(l.waiters, w); i >= 0 {
		l.waiters = slices.Delete(l.waiters, i, i+1)
		return nil, err
	}
	// The slot came just as the wait ended, so it goes to the next waiter.
	s.release(id)
	return nil, err
}

// releaser frees a slot in lane id once, however often it is called.
func (s *Scheduler) releaser(id LaneID) func() {
	return sync.OnceFunc(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.release(id)
	})
}

// release frees a slot and hands it on; the caller holds mu.
func (s *Scheduler) release(id LaneID) {
	s.lanes[id].active--
	s.grant(id)
}

// grant gives free slots in lane id to waiters, the tenant with the least use for its share first; the caller holds mu.
func (s *Scheduler) grant(id LaneID) {
	l, limit := &s.lanes[id], s.lane(id).MaxActive
	for len(l.waiters) > 0 && (limit == 0 || l.active < limit) {
		// Ties go to the earliest waiter, since MinFunc returns the first minimum.
		next := slices.MinFunc(l.waiters, func(a, b *waiter) int {
			return cmp.Compare(s.served(a.tenant), s.served(b.tenant))
		})
		l.waiters = slices.DeleteFunc(l.waiters, func(w *waiter) bool { return w == next })
		l.active++
		close(next.granted)
	}
}

// served is tenant's recent use for its share; the caller holds mu.
func (s *Scheduler) served(tenant string) float64 {
	return s.refresh(tenant).usage / s.budget(tenant).Share
}

// budget returns tenant's budget with its defaults filled in; the caller holds mu.
func (s *Scheduler) budget(tenant string) Budget {
	b, ok := s.cfg.Budgets[tenant]
	if !ok {
		b = s.cfg.Default
	}
	b.Burst = cmp.Or(b.Burst, b.Rate)
	b.Share = cmp.Or(b.Share, 1)
	b.WhenOver = cmp.Or(b.WhenOver, Queue)
	return b
}

// refresh returns tenant's state brought up to now, creating it with a full budget; the caller holds mu.
func (s *Scheduler) refresh(name string) *tenant {
	now := time.Now()
	b := s.budget(name)
	t, ok := s.tenants[name]
	if !ok {
		t = &tenant{tokens: b.Burst, updated: now}
		s.tenants[name] = t
	}
	elapsed := now.Sub(t.updated).Seconds()
	t.tokens = min(b.Burst, t.tokens+b.Rate*elapsed)
	t.usage *= math.Exp2(-elapsed / usageHalfLife.Seconds())
	t.updated = now
	return t
}

// forgetIdle drops tenants that owe nothing, have used little lately and wait for no slot; the caller holds mu.
func (s *Scheduler) forgetIdle() {
	waiting := map[string]bool{}
	for _, l := range s.lanes {
		for _, w := range l.waiters {
			waiting[w.tenant] = true
		}
	}
	for name := range s.tenants {
		if t := s.refresh(name); !waiting[name] && t.tokens >= s.budget(name).Burst && t.usage < 1 {
			delete(s.tenants, name)
		}
	}
}

func (s *Scheduler) lane(id LaneID) Lane {
	if id == Slow {
		return s.cfg.Slow
	}
	return s.cfg.Fast
}

func (s *Scheduler) queueTimeout(id LaneID) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == Slow {
		return cmp.Or(s.cfg.Slow.QueueTimeout, DefaultSlowQueueTimeout)
	}
	return cmp.Or(s.cfg.Fast.QueueTimeout, DefaultQueueTimeout)
}

// waiting counts the statements waiting for a slot in lane id.
func (s *Scheduler) waiting(id LaneID) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.lanes[id].waiters)
}
