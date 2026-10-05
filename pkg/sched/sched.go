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
	Controller Controller        // moves the fast lane's limit under Fast.MaxActive; nil keeps it at Fast.MaxActive
}

// AdjustInterval is how often Run asks the Controller for a new limit.
const AdjustInterval = time.Second

// Signal is what the scheduler saw over one AdjustInterval.
type Signal struct {
	Slowdown  float64 // geometric mean of finished statements' time over their usual time; 0 when none finished
	LockWaits int     // sessions waiting on a lock, as last reported
	Saturated bool    // every slot under the limit was taken at some point, so the limit held statements back
}

// Controller sets the fast lane's limit; AIMD is the default, and a PID controller can take its place.
type Controller interface {
	Adjust(limit int, s Signal) int
}

// AIMD grows the limit by one each calm interval in which it held statements back and shrinks it by a fraction when overloaded, as TCP does.
type AIMD struct {
	Floor         int     // the lowest limit; 0 means 1
	Backoff       float64 // what the limit is multiplied by when overloaded; 0 means 0.9
	MaxSlowdown   float64 // the slowdown that counts as overload; 0 means 2
	LockWaitShare float64 // the share of the limit waiting on locks that counts as overload; 0 means 0.25
}

// Adjust returns the next limit: smaller when statements slow down or wait on locks, one larger when calm and full, else the same.
func (a AIMD) Adjust(limit int, s Signal) int {
	floor := max(a.Floor, 1)
	overloaded := s.Slowdown > cmp.Or(a.MaxSlowdown, 2) || float64(s.LockWaits) > cmp.Or(a.LockWaitShare, 0.25)*float64(limit)
	switch {
	case overloaded:
		// Rounding down alone could leave a small limit where it is.
		return max(floor, min(limit-1, int(float64(limit)*cmp.Or(a.Backoff, 0.9))))
	case s.Slowdown > 0 && s.Saturated:
		return limit + 1
	}
	return max(floor, limit)
}

// Priority orders statements waiting for a slot; under overload, best-effort ones are shed.
type Priority int

const (
	BestEffort Priority = iota - 1
	Normal
	Critical
)

var (
	ErrOverBudget = errors.New("the tenant's cost budget is spent")
	ErrBusy       = errors.New("no slot came free in time")
	ErrShed       = errors.New("best-effort statements are shed while the server is overloaded")
)

// Scheduler is safe for concurrent use.
type Scheduler struct {
	mu         sync.Mutex
	cfg        Config
	tenants    map[string]*tenant
	lanes      [2]lane
	limit      int     // the fast lane's limit now; 0 means none
	overloaded bool    // the limit last moved down, so best-effort statements don't wait
	slowdowns  float64 // the sum of ln(slowdown) this interval
	finished   int     // statements finished this interval
	lockWaits  int     // sessions waiting on a lock, as last reported
	saturated  bool    // every fast slot was taken at some point this interval
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
	prio    Priority
	shed    bool          // set before granted is closed when the waiter is shed instead
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
	if cfg.Controller == nil || s.limit == 0 {
		s.limit, s.overloaded = cfg.Fast.MaxActive, false
	}
	s.limit = min(s.limit, cfg.Fast.MaxActive)
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

// Acquire waits for a slot in lane, handed to the highest priority and then the least-served tenant first, and returns the func that frees it.
func (s *Scheduler) Acquire(ctx context.Context, tenant string, id LaneID, prio Priority) (release func(), err error) {
	s.mu.Lock()
	l, limit := &s.lanes[id], s.max(id)
	if limit == 0 || (l.active < limit && len(l.waiters) == 0) {
		s.take(id)
		s.mu.Unlock()
		return s.releaser(id), nil
	}
	if id == Fast {
		s.saturated = true
		if prio == BestEffort && s.overloaded {
			s.mu.Unlock()
			return nil, ErrShed
		}
	}
	w := &waiter{tenant: tenant, prio: prio, granted: make(chan struct{})}
	l.waiters = append(l.waiters, w)
	s.mu.Unlock()

	timer := time.NewTimer(s.queueTimeout(id))
	defer timer.Stop()
	select {
	case <-w.granted:
		if w.shed {
			return nil, ErrShed
		}
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
	if w.shed {
		return nil, ErrShed
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

// grant gives free slots in lane id to waiters, by priority and then the tenant with the least use for its share; the caller holds mu.
func (s *Scheduler) grant(id LaneID) {
	l, limit := &s.lanes[id], s.max(id)
	for len(l.waiters) > 0 && (limit == 0 || l.active < limit) {
		// Ties go to the earliest waiter, since MinFunc returns the first minimum.
		next := slices.MinFunc(l.waiters, func(a, b *waiter) int {
			return cmp.Or(cmp.Compare(b.prio, a.prio), cmp.Compare(s.served(a.tenant), s.served(b.tenant)))
		})
		l.waiters = slices.DeleteFunc(l.waiters, func(w *waiter) bool { return w == next })
		s.take(id)
		close(next.granted)
	}
}

// take counts a slot in lane id as taken; the caller holds mu.
func (s *Scheduler) take(id LaneID) {
	s.lanes[id].active++
	if id == Fast && s.limit > 0 && s.lanes[id].active >= s.limit {
		s.saturated = true
	}
}

// max returns how many statements lane id runs at once, 0 meaning no limit; the caller holds mu.
func (s *Scheduler) max(id LaneID) int {
	if id == Slow {
		return s.cfg.Slow.MaxActive
	}
	return s.limit
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

func (s *Scheduler) queueTimeout(id LaneID) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == Slow {
		return cmp.Or(s.cfg.Slow.QueueTimeout, DefaultSlowQueueTimeout)
	}
	return cmp.Or(s.cfg.Fast.QueueTimeout, DefaultQueueTimeout)
}

// Run adjusts the fast lane's limit every AdjustInterval until ctx ends.
func (s *Scheduler) Run(ctx context.Context) {
	tick := time.Tick(AdjustInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			s.adjust()
		}
	}
}

// adjust asks the Controller for a new limit from what this interval saw, and starts the next interval.
func (s *Scheduler) adjust() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Controller == nil || s.limit == 0 {
		return
	}
	sig := Signal{LockWaits: s.lockWaits, Saturated: s.saturated}
	if s.finished > 0 {
		sig.Slowdown = math.Exp(s.slowdowns / float64(s.finished))
	}
	// A limit of 0 means none, so the least a Controller can set is 1.
	limit := min(max(s.cfg.Controller.Adjust(s.limit, sig), 1), s.cfg.Fast.MaxActive)
	if limit != s.limit {
		s.overloaded = limit < s.limit
	}
	s.limit = limit
	s.slowdowns, s.finished = 0, 0
	s.saturated = s.lanes[Fast].active >= limit || len(s.lanes[Fast].waiters) > 0
	if s.overloaded {
		s.shed()
	}
	s.grant(Fast)
}

// shed turns away the best-effort statements waiting for a fast slot; the caller holds mu.
func (s *Scheduler) shed() {
	l := &s.lanes[Fast]
	l.waiters = slices.DeleteFunc(l.waiters, func(w *waiter) bool {
		if w.prio != BestEffort {
			return false
		}
		w.shed = true
		close(w.granted)
		return true
	})
}

// Finished reports that a statement ran slowdown times as long as it usually does.
func (s *Scheduler) Finished(slowdown float64) {
	if slowdown <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.slowdowns += math.Log(slowdown)
	s.finished++
}

// LockWaits reports how many sessions wait on a lock now.
func (s *Scheduler) LockWaits(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lockWaits = n
}

// Limit returns how many statements the fast lane runs at once now; 0 means no limit.
func (s *Scheduler) Limit() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.limit
}

// waiting counts the statements waiting for a slot in lane id.
func (s *Scheduler) waiting(id LaneID) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.lanes[id].waiters)
}

// Transfer moves cost from one tenant to another, as from a tenant kept waiting on locks to the tenant holding them.
func (s *Scheduler) Transfer(from, to string, cost float64) {
	if cost <= 0 || from == to {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, t := s.budget(from), s.refresh(from)
	if b.Rate > 0 {
		t.tokens = min(b.Burst, t.tokens+cost)
	}
	t.usage = max(0, t.usage-cost)
	b, t = s.budget(to), s.refresh(to)
	if b.Rate > 0 {
		t.tokens -= cost
	}
	t.usage += cost
	if len(s.tenants) > maxTenants {
		s.forgetIdle()
	}
}
