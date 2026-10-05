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

// shutPoll is how often a statement waiting on a shut budget looks again, since it has no rate to work out its wait from.
const shutPoll = 100 * time.Millisecond

// Budget is one tenant's allowance of cost units.
type Budget struct {
	Rate      float64 // units added each second; 0 means the tenant is not limited, and below 0 that it may spend nothing for now
	Burst     float64 // the most units saved up; 0 means Rate, a second's worth
	Share     float64 // the tenant's weight when slots are handed out; 0 means 1
	MinCharge float64 // the least any statement costs, so a tight loop of cheap ones still counts
	WhenOver  Action  // "" means Queue
}

// Lane is a pool of slots, each running one statement at a time.
type Lane struct {
	MaxActive    int           // statements running at once; 0 means no limit, and below 0 that none may run for now
	QueueTimeout time.Duration // the longest a statement waits for its slot or budget; 0 means the lane's default
	// A queue that has not been empty for StandingAfter stands: it serves the newest waiter first and drops those that waited
	// longer than StandingTimeout, as CoDel does; 0 for either turns this off.
	StandingAfter, StandingTimeout time.Duration
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
	// DemoteAfter moves a fast-lane statement running longer into the slow lane's count; 0 never does.
	DemoteAfter time.Duration
}

// AdjustInterval is how often Run asks the Controller for a new limit.
const AdjustInterval = time.Second

// Signal is what the scheduler saw over one AdjustInterval.
type Signal struct {
	Slowdown  float64 // geometric mean of finished statements' time over their usual time; 0 when none with a usual time finished
	Finished  int     // fast-lane statements that finished, with a usual time or not
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
	case s.Saturated && (s.Slowdown > 0 || s.Finished > 0):
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
	ErrHeld       = errors.New("best-effort statements are held back")
)

// Scheduler is safe for concurrent use.
type Scheduler struct {
	mu         sync.Mutex
	cfg        Config
	tenants    map[string]*tenant
	lanes      [2]lane
	limit      int            // the fast lane's limit now; 0 means none
	overloaded bool           // the limit last moved down, so best-effort statements don't wait
	slowdowns  float64        // the sum of ln(slowdown) this interval
	finished   int            // statements with a usual time finished this interval
	ended      int            // fast-lane statements finished this interval
	lockWaits  int            // sessions waiting on a lock, as last reported
	saturated  bool           // every fast slot was taken at some point this interval
	held       bool           // best-effort statements wait, however many slots are free
	caps       map[string]int // the most statements a tenant may run at once, for tenants capped
	running    map[string]int // statements each tenant runs now, in both lanes
	demand     Demand         // since the last TakeDemand
}

// tenant is one tenant's state, brought up to date by refresh before each use.
type tenant struct {
	tokens  float64   // cost units left; below zero, what the tenant owes
	usage   float64   // cost charged, fading with usageHalfLife
	updated time.Time // when tokens and usage were last brought up to date
}

type lane struct {
	active    int
	waiters   []*waiter // in arrival order
	lastEmpty time.Time // when the queue was last empty, to tell a standing queue
}

type waiter struct {
	tenant  string
	prio    Priority
	since   time.Time     // when it began to wait
	shed    bool          // set before granted is closed when the waiter is shed instead
	dropped bool          // set before granted is closed when a standing queue drops the waiter
	slot    *slot         // set before granted is closed when the waiter is given a slot
	granted chan struct{} // closed when the waiter is given a slot or shed
}

// New returns a Scheduler with cfg.
func New(cfg Config) *Scheduler {
	s := &Scheduler{tenants: map[string]*tenant{}, caps: map[string]int{}, running: map[string]int{},
		demand: Demand{Spent: map[string]float64{}, Starved: map[string]bool{}}}
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
	// A lane that was shut, as before a fleet's first lease, opens at its full limit.
	if cfg.Controller == nil || s.limit <= 0 {
		s.limit = cfg.Fast.MaxActive
	}
	if cfg.Controller == nil {
		s.overloaded = false
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
		if b.Rate < 0 {
			s.demand.Starved[tenant] = true
			s.mu.Unlock()
			wait := min(shutPoll, time.Until(deadline))
			if wait <= 0 {
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
		if b.Rate > 0 && t.tokens < 0 {
			s.demand.Starved[tenant] = true
			switch b.WhenOver {
			case Reject:
				s.mu.Unlock()
				return 0, ErrOverBudget
			case SlowLane:
				lane = Slow
			default:
				wait := time.Duration(math.Ceil(-t.tokens / b.Rate * float64(time.Second)))
				s.mu.Unlock()
				if dl, ok := ctx.Deadline(); ok && time.Now().Add(wait).After(dl) {
					return 0, context.DeadlineExceeded
				}
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
	s.demand.Spent[name] += cost
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
	s.demand.Spent[tenant] -= cost
}

// Acquire waits for a slot in lane, handed to the highest priority and then the least-served tenant first, and returns the func that frees it.
func (s *Scheduler) Acquire(ctx context.Context, tenant string, id LaneID, prio Priority) (release func(), err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	l, limit := &s.lanes[id], s.max(id)
	w := &waiter{tenant: tenant, prio: prio, since: time.Now(), granted: make(chan struct{})}
	full := limit != 0 && l.active >= max(limit, 0)
	if !full && s.eligible(w) && !slices.ContainsFunc(l.waiters, s.eligible) {
		sl := s.take(id, tenant)
		s.mu.Unlock()
		return s.releaser(sl), nil
	}
	if id == Fast && full {
		s.saturated = true
		if prio == BestEffort && s.overloaded {
			s.mu.Unlock()
			return nil, ErrShed
		}
	}
	timeout := s.laneTimeout(id)
	if s.standing(id, w.since) {
		// A statement that finds the queue standing gets only the short wait it would be dropped after.
		timeout = min(timeout, s.lane(id).StandingTimeout)
	}
	if len(l.waiters) == 0 {
		l.lastEmpty = w.since
	}
	l.waiters = append(l.waiters, w)
	s.demand.Slots[id] = max(s.demand.Slots[id], l.active+len(l.waiters))
	s.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-w.granted:
		switch {
		case w.shed:
			return nil, ErrShed
		case w.dropped:
			return nil, ErrBusy
		}
		return s.releaser(w.slot), nil
	case <-ctx.Done():
		err = ctx.Err()
	case <-timer.C:
		err = ErrBusy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if i := slices.Index(l.waiters, w); i >= 0 {
		l.waiters = slices.Delete(l.waiters, i, i+1)
		s.dequeued(id)
		if errors.Is(err, ErrBusy) && prio == BestEffort && s.held {
			err = ErrHeld
		}
		return nil, err
	}
	switch {
	case w.shed:
		return nil, ErrShed
	case w.dropped:
		return nil, ErrBusy
	}
	// The slot came just as the wait ended, so it goes to the next waiter.
	s.release(w.slot)
	return nil, err
}

// Force gives tenant a slot in lane id at once, past the limit, holds and caps, as for a session whose locks others wait on.
func (s *Scheduler) Force(tenant string, id LaneID) (release func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.releaser(s.take(id, tenant))
}

// slot is one statement's place in a lane.
type slot struct {
	lane   LaneID
	tenant string
	demote *time.Timer // moves it to the slow lane's count; nil when it never moves
	freed  bool
}

// releaser frees sl once, however often it is called.
func (s *Scheduler) releaser(sl *slot) func() {
	return sync.OnceFunc(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.release(sl)
	})
}

// release frees sl and hands slots on; the caller holds mu.
func (s *Scheduler) release(sl *slot) {
	if sl.freed {
		return
	}
	sl.freed = true
	if sl.demote != nil {
		sl.demote.Stop()
	}
	s.lanes[sl.lane].active--
	if sl.lane == Fast {
		s.ended++
	}
	if s.running[sl.tenant]--; s.running[sl.tenant] <= 0 {
		delete(s.running, sl.tenant)
	}
	// The tenant's cap may have held up a waiter in either lane.
	s.grant(Fast)
	s.grant(Slow)
}

// demote counts sl, which has run in the fast lane past DemoteAfter, in the slow lane instead; the caller holds mu.
func (s *Scheduler) demote(sl *slot) {
	if sl.freed || sl.lane != Fast {
		return
	}
	s.lanes[Fast].active--
	s.lanes[Slow].active++
	sl.lane = Slow
	s.grant(Fast)
}

// eligible reports whether w may take a slot once one is free: a hold or its tenant's cap may keep it waiting; the caller holds mu.
func (s *Scheduler) eligible(w *waiter) bool {
	if s.held && w.prio == BestEffort {
		return false
	}
	n := s.caps[w.tenant]
	return n == 0 || s.running[w.tenant] < n
}

// grant gives free slots in lane id to eligible waiters, by priority and then the tenant with the least use for its share; the caller holds mu.
func (s *Scheduler) grant(id LaneID) {
	l, limit := &s.lanes[id], s.max(id)
	for limit == 0 || l.active < limit {
		now := time.Now()
		standing := s.standing(id, now)
		if standing {
			// The clients of statements that waited this long are likely gone, and serving them first keeps everyone waiting.
			l.waiters = slices.DeleteFunc(l.waiters, func(w *waiter) bool {
				if now.Sub(w.since) <= s.lane(id).StandingTimeout {
					return false
				}
				w.dropped = true
				close(w.granted)
				return true
			})
		}
		var next *waiter
		for _, w := range l.waiters {
			if s.eligible(w) && (next == nil || s.before(w, next, standing)) {
				next = w
			}
		}
		if next == nil {
			s.dequeued(id)
			return
		}
		l.waiters = slices.DeleteFunc(l.waiters, func(w *waiter) bool { return w == next })
		s.dequeued(id)
		next.slot = s.take(id, next.tenant)
		close(next.granted)
	}
}

// before reports whether a goes ahead of b: by priority, then by use for share, then by arrival, the newest first in a standing
// queue and the oldest first otherwise; the caller holds mu.
func (s *Scheduler) before(a, b *waiter, standing bool) bool {
	arrival := a.since.Compare(b.since)
	if standing {
		arrival = -arrival
	}
	return cmp.Or(cmp.Compare(b.prio, a.prio), cmp.Compare(s.served(a.tenant), s.served(b.tenant)), arrival) < 0
}

// standing reports whether lane id's queue has not been empty for StandingAfter at now; the caller holds mu.
func (s *Scheduler) standing(id LaneID, now time.Time) bool {
	l, cfg := &s.lanes[id], s.lane(id)
	return cfg.StandingAfter > 0 && cfg.StandingTimeout > 0 && len(l.waiters) > 0 && now.Sub(l.lastEmpty) >= cfg.StandingAfter
}

// dequeued notes when lane id's queue empties, after waiters left it; the caller holds mu.
func (s *Scheduler) dequeued(id LaneID) {
	if l := &s.lanes[id]; len(l.waiters) == 0 {
		l.lastEmpty = time.Now()
	}
}

// lane returns lane id's settings; the caller holds mu.
func (s *Scheduler) lane(id LaneID) Lane {
	if id == Slow {
		return s.cfg.Slow
	}
	return s.cfg.Fast
}

// take gives tenant a slot in lane id; the caller holds mu.
func (s *Scheduler) take(id LaneID, tenant string) *slot {
	s.lanes[id].active++
	s.running[tenant]++
	s.demand.Slots[id] = max(s.demand.Slots[id], s.lanes[id].active+len(s.lanes[id].waiters))
	if id == Fast && s.limit > 0 && s.lanes[id].active >= s.limit {
		s.saturated = true
	}
	sl := &slot{lane: id, tenant: tenant}
	if d := s.cfg.DemoteAfter; id == Fast && d > 0 {
		sl.demote = time.AfterFunc(d, func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.demote(sl)
		})
	}
	return sl
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
		t = &tenant{tokens: max(b.Burst, 0), updated: now}
		s.tenants[name] = t
	}
	elapsed := now.Sub(t.updated).Seconds()
	// A shut budget neither fills nor drains, so it opens where it stopped.
	if b.Rate >= 0 {
		t.tokens = min(b.Burst, t.tokens+b.Rate*elapsed)
	}
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
	return s.laneTimeout(id)
}

// laneTimeout returns lane id's queue timeout; the caller holds mu.
func (s *Scheduler) laneTimeout(id LaneID) time.Duration {
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
	if s.cfg.Controller == nil || s.limit <= 0 {
		return
	}
	sig := Signal{Finished: s.ended, LockWaits: s.lockWaits, Saturated: s.saturated}
	if s.finished > 0 {
		sig.Slowdown = math.Exp(s.slowdowns / float64(s.finished))
	}
	// A limit of 0 means none, so the least a Controller can set is 1.
	limit := min(max(s.cfg.Controller.Adjust(s.limit, sig), 1), s.cfg.Fast.MaxActive)
	if limit != s.limit {
		s.overloaded = limit < s.limit
	}
	s.limit = limit
	s.slowdowns, s.finished, s.ended = 0, 0, 0
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
	s.dequeued(Fast)
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
	s.demand.Spent[from] -= cost
	b, t = s.budget(to), s.refresh(to)
	if b.Rate > 0 {
		t.tokens -= cost
	}
	t.usage += cost
	s.demand.Spent[to] += cost
	if len(s.tenants) > maxTenants {
		s.forgetIdle()
	}
}

// HoldBestEffort keeps best-effort statements waiting for a slot while on, as while a standby lags.
func (s *Scheduler) HoldBestEffort(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.held = on
	s.grant(Fast)
	s.grant(Slow)
}

// CapTenant lets tenant run at most n statements at once across both lanes; 0 lifts the cap.
func (s *Scheduler) CapTenant(tenant string, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > 0 {
		s.caps[tenant] = n
	} else {
		delete(s.caps, tenant)
	}
	s.grant(Fast)
	s.grant(Slow)
}

// TrueUp charges tenant the difference between a statement's cost when it ran, actual, and what it was charged; less is paid back.
func (s *Scheduler) TrueUp(tenant string, charged, actual float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, t := s.budget(tenant), s.refresh(tenant)
	diff := max(actual, b.MinCharge) - max(charged, b.MinCharge)
	if b.Rate > 0 {
		t.tokens = min(b.Burst, t.tokens-diff)
	}
	t.usage = max(0, t.usage+diff)
	s.demand.Spent[tenant] += diff
}

// Demand is what statements asked of the scheduler since the last TakeDemand, for sharing limits across instances.
type Demand struct {
	Spent   map[string]float64 // cost charged, by tenant
	Starved map[string]bool    // tenants that found their budget spent
	Slots   [2]int             // the most statements running or waiting at once, by lane
	Running [2]int             // statements running when it was taken, by lane
}

// TakeDemand returns the demand since its last call and starts counting again.
func (s *Scheduler) TakeDemand() Demand {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.demand
	for id := range s.lanes {
		d.Running[id] = s.lanes[id].active
	}
	for t, n := range d.Spent {
		if n <= 0 {
			delete(d.Spent, t)
		}
	}
	s.demand = Demand{Spent: map[string]float64{}, Starved: map[string]bool{}}
	for id := range s.lanes {
		s.demand.Slots[id] = s.lanes[id].active + len(s.lanes[id].waiters)
	}
	return d
}
