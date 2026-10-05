package sched

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestBudgetRefillsAtItsRate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Budgets: map[string]Budget{"acme": {Rate: 100, Burst: 200, WhenOver: Reject}}})

		reserve(t, s, "acme", Fast)
		s.Charge("acme", 250)
		// 50 units owed: nothing runs until the budget is back above zero, half a second later.
		if _, err := s.Reserve(t.Context(), "acme"); !errors.Is(err, ErrOverBudget) {
			t.Fatalf("Reserve with the budget spent = %v; want ErrOverBudget", err)
		}
		time.Sleep(501 * time.Millisecond)
		reserve(t, s, "acme", Fast)
	})
}

func TestBudgetNeverHoldsMoreThanBurst(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Budgets: map[string]Budget{"acme": {Rate: 100, Burst: 200, WhenOver: Reject}}})

		time.Sleep(time.Hour)
		s.Charge("acme", 250)

		if _, err := s.Reserve(t.Context(), "acme"); !errors.Is(err, ErrOverBudget) {
			t.Errorf("an hour of saving let 250 units through a burst of 200: %v", err)
		}
	})
}

func TestMinChargeCountsCheapStatements(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Budgets: map[string]Budget{"acme": {Rate: 10, Burst: 10, MinCharge: 6, WhenOver: Reject}}})

		for range 2 {
			reserve(t, s, "acme", Fast)
			s.Charge("acme", 0.01)
		}

		if _, err := s.Reserve(t.Context(), "acme"); !errors.Is(err, ErrOverBudget) {
			t.Errorf("third statement = %v; want ErrOverBudget after two minimum charges of 6", err)
		}
	})
}

func TestOverBudgetQueuesUntilRefilled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Fast: Lane{QueueTimeout: 5 * time.Second}, Budgets: map[string]Budget{"acme": {Rate: 100, Burst: 100}}})
		s.Charge("acme", 300)

		start := time.Now()
		reserve(t, s, "acme", Fast)

		// 200 units owed at 100 a second.
		if waited := time.Since(start); waited < 2*time.Second || waited > 2*time.Second+time.Millisecond {
			t.Errorf("waited %v; want 2s", waited)
		}
	})
}

func TestOverBudgetQueueGivesUpPastTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Fast: Lane{QueueTimeout: time.Second}, Budgets: map[string]Budget{"acme": {Rate: 100, Burst: 100}}})
		s.Charge("acme", 600)

		start := time.Now()
		_, err := s.Reserve(t.Context(), "acme")

		// The wait is known in advance, so a statement that would wait too long fails at once.
		if !errors.Is(err, ErrOverBudget) || time.Since(start) != 0 {
			t.Errorf("Reserve = %v after %v; want ErrOverBudget at once", err, time.Since(start))
		}
	})
}

func TestOverBudgetGoesToSlowLane(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Budgets: map[string]Budget{"acme": {Rate: 100, Burst: 100, WhenOver: SlowLane}}})

		reserve(t, s, "acme", Fast)
		s.Charge("acme", 500)

		reserve(t, s, "acme", Slow)
	})
}

func TestTenantWithoutBudgetIsNotLimited(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Budgets: map[string]Budget{"acme": {Rate: 1, Burst: 1, WhenOver: Reject}}})
		for range 100 {
			reserve(t, s, "other", Fast)
			s.Charge("other", 1e9)
		}
	})
}

func TestDefaultBudgetAppliesToUnlistedTenants(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Default: Budget{Rate: 1, Burst: 1, WhenOver: Reject}})
		reserve(t, s, "anyone", Fast)
		s.Charge("anyone", 10)
		if _, err := s.Reserve(t.Context(), "anyone"); !errors.Is(err, ErrOverBudget) {
			t.Errorf("Reserve = %v; want the default budget to apply", err)
		}
	})
}

func TestSpendChecksAndChargesAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Budgets: map[string]Budget{"acme": {Rate: 1, Burst: 100, WhenOver: Reject}}})
		// Statements that all passed Reserve before any was charged still can't all spend the same budget.
		for range 3 {
			reserve(t, s, "acme", Fast)
		}

		var errs []error
		for range 3 {
			_, err := s.Spend(t.Context(), "acme", 80)
			errs = append(errs, err)
		}

		if errs[0] != nil || errs[1] != nil || !errors.Is(errs[2], ErrOverBudget) {
			t.Errorf("Spend errors %v; want the third over budget", errs)
		}
	})
}

func TestSpendWaitsInQueueAndGoesToSlowLane(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Budgets: map[string]Budget{"queued": {Rate: 100, Burst: 100}, "slowed": {Rate: 100, Burst: 100, WhenOver: SlowLane}}})
		for _, tenant := range []string{"queued", "slowed"} {
			s.Spend(t.Context(), tenant, 150)
		}

		// The slowed tenant goes first, since its debt is paid back while the queued one waits.
		slowed, _ := s.Spend(t.Context(), "slowed", 10)
		start := time.Now()
		queued, err := s.Spend(t.Context(), "queued", 10)
		waited := time.Since(start)

		if err != nil || queued != Fast || waited != 500*time.Millisecond || slowed != Slow {
			t.Errorf("queued in %v lane after %v (%v), slowed in %v lane; want fast after 500ms, slow", queued, waited, err, slowed)
		}
	})
}

func TestRefundGivesBackACharge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Budgets: map[string]Budget{"acme": {Rate: 1, Burst: 100, MinCharge: 30, WhenOver: Reject}}})
		s.Spend(t.Context(), "acme", 10)
		s.Spend(t.Context(), "acme", 80)
		s.Refund("acme", 10)
		s.Refund("acme", 80)

		if s.Spent("acme") {
			t.Error("the budget is still spent after both charges were refunded")
		}
	})
}

func TestTransferMovesCostBetweenTenants(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Budgets: map[string]Budget{"holder": {Rate: 1, Burst: 100, WhenOver: Reject}, "waiter": {Rate: 1, Burst: 100, WhenOver: Reject}}})
		s.Charge("waiter", 120)

		// The waiter gets back more than it owes; the holder pays from its 100.
		s.Transfer("waiter", "holder", 50)
		if s.Spent("waiter") || s.Spent("holder") {
			t.Errorf("after 50: waiter spent %v, holder spent %v; want neither", s.Spent("waiter"), s.Spent("holder"))
		}
		s.Transfer("waiter", "holder", 60)
		if s.Spent("waiter") || !s.Spent("holder") {
			t.Errorf("after 110: waiter spent %v, holder spent %v; want only the holder", s.Spent("waiter"), s.Spent("holder"))
		}
	})
}

func TestSpentReportsDebt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Budgets: map[string]Budget{"acme": {Rate: 10, Burst: 10}}})
		s.Charge("acme", 10)
		if s.Spent("acme") {
			t.Error("an empty budget counts as spent; want only a debt to")
		}
		s.Charge("acme", 1)
		if !s.Spent("acme") || s.Spent("other") {
			t.Errorf("Spent = %v for acme, %v for a tenant without budget; want true, false", s.Spent("acme"), s.Spent("other"))
		}
	})
}

func TestSlotsWaitAndTimeOut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Fast: Lane{MaxActive: 1, QueueTimeout: time.Second}})
		release := acquire(t, s, "a", Fast)

		start := time.Now()
		if _, err := s.Acquire(t.Context(), "b", Fast, Normal); !errors.Is(err, ErrBusy) || time.Since(start) != time.Second {
			t.Fatalf("Acquire with no slot = %v after %v; want ErrBusy after 1s", err, time.Since(start))
		}

		release()
		release()
		// Releasing twice frees one slot, not two.
		acquire(t, s, "b", Fast)
		if _, err := s.Acquire(t.Context(), "c", Fast, Normal); !errors.Is(err, ErrBusy) {
			t.Errorf("a second slot came free after a double release: %v", err)
		}
	})
}

func TestSlotGoesToLeastServedTenant(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Fast: Lane{MaxActive: 1, QueueTimeout: time.Minute},
			Budgets: map[string]Budget{"heavy": {Share: 1}, "light": {Share: 1}, "vip": {Share: 10}}})
		s.Charge("heavy", 1000)
		s.Charge("light", 10)
		s.Charge("vip", 50)
		release := acquire(t, s, "heavy", Fast)

		var mu sync.Mutex
		var order []string
		var wg sync.WaitGroup
		for _, tenant := range []string{"heavy", "light", "vip"} {
			wg.Go(func() {
				done := acquire(t, s, tenant, Fast)
				mu.Lock()
				order = append(order, tenant)
				mu.Unlock()
				done()
			})
			synctest.Wait()
		}
		release()
		wg.Wait()

		// vip used most after light but has ten times the share: 50/10 < 10/1 < 1000/1.
		if !slices.Equal(order, []string{"vip", "light", "heavy"}) {
			t.Errorf("slots went to %v; want vip, light, heavy", order)
		}
	})
}

func TestUsageFadesOverTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Fast: Lane{MaxActive: 1, QueueTimeout: time.Hour}})
		s.Charge("old", 1000)
		time.Sleep(2 * time.Minute)
		s.Charge("new", 10)
		release := acquire(t, s, "x", Fast)

		var first string
		var once sync.Once
		var wg sync.WaitGroup
		for _, tenant := range []string{"new", "old"} {
			wg.Go(func() {
				done := acquire(t, s, tenant, Fast)
				once.Do(func() { first = tenant })
				done()
			})
			synctest.Wait()
		}
		release()
		wg.Wait()

		// Twelve half-lives later, 1000 units count for less than 1.
		if first != "old" {
			t.Errorf("slot went first to %q; want old, whose usage has faded", first)
		}
	})
}

func TestWaitEndsWithContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Fast: Lane{MaxActive: 1, QueueTimeout: time.Hour}})
		acquire(t, s, "a", Fast)
		ctx, cancel := context.WithCancel(t.Context())
		time.AfterFunc(time.Second, cancel)

		if _, err := s.Acquire(ctx, "b", Fast, Normal); !errors.Is(err, context.Canceled) {
			t.Errorf("Acquire = %v; want the context's error", err)
		}
		// The cancelled waiter left the queue, so it can't take the next free slot.
		if n := s.waiting(Fast); n != 0 {
			t.Errorf("%d waiters left in the queue", n)
		}
	})
}

func TestLanesHaveSeparateSlots(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Fast: Lane{MaxActive: 1}, Slow: Lane{MaxActive: 1}})
		acquire(t, s, "a", Fast)
		acquire(t, s, "b", Slow)
	})
}

func TestConfigureKeepsBalances(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Budgets: map[string]Budget{"acme": {Rate: 100, Burst: 100, WhenOver: Reject}}})
		s.Charge("acme", 300)

		s.Configure(Config{Budgets: map[string]Budget{"acme": {Rate: 1000, Burst: 1000, WhenOver: Reject}}})

		// 200 units are still owed; at the new rate they are paid back in 0.2s.
		if _, err := s.Reserve(t.Context(), "acme"); !errors.Is(err, ErrOverBudget) {
			t.Fatalf("Reserve right after reload = %v; want the debt kept", err)
		}
		time.Sleep(201 * time.Millisecond)
		reserve(t, s, "acme", Fast)
	})
}

func TestConfigureResizesLanes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Fast: Lane{MaxActive: 1, QueueTimeout: time.Hour}})
		acquire(t, s, "a", Fast)
		got := make(chan struct{})
		go func() {
			acquire(t, s, "b", Fast)
			close(got)
		}()
		synctest.Wait()

		s.Configure(Config{Fast: Lane{MaxActive: 2, QueueTimeout: time.Hour}})

		synctest.Wait()
		select {
		case <-got:
		default:
			t.Error("a waiter did not get the slot a larger lane added")
		}
	})
}

func TestAIMD(t *testing.T) {
	a := AIMD{Floor: 2}
	for name, tc := range map[string]struct {
		limit int
		sig   Signal
		want  int
	}{
		"slow statements back off":         {10, Signal{Slowdown: 3, Saturated: true}, 9},
		"lock waits back off":              {20, Signal{Slowdown: 1, LockWaits: 6, Saturated: true}, 18},
		"a few lock waits are normal":      {20, Signal{Slowdown: 1, LockWaits: 5, Saturated: true}, 21},
		"never below the floor":            {2, Signal{Slowdown: 3}, 2},
		"calm and full grows by one":       {10, Signal{Slowdown: 1.5, Saturated: true}, 11},
		"calm with room to spare holds":    {10, Signal{Slowdown: 1}, 10},
		"nothing finished holds":           {10, Signal{Saturated: true}, 10},
		"backing off always takes one off": {3, Signal{Slowdown: 3}, 2},
	} {
		if got := a.Adjust(tc.limit, tc.sig); got != tc.want {
			t.Errorf("%s: Adjust(%d, %+v) = %d; want %d", name, tc.limit, tc.sig, got, tc.want)
		}
	}
}

func TestAdaptiveLimitFollowsLoad(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Fast: Lane{MaxActive: 8, QueueTimeout: time.Hour}, Controller: AIMD{Floor: 2}})
		go s.Run(t.Context())
		for range 8 {
			acquire(t, s, "a", Fast)
		}
		highest := 0
		ramp := func(slowdown float64) {
			for range 30 {
				s.Finished(slowdown)
				nextInterval()
				highest = max(highest, s.Limit())
			}
		}

		ramp(4)
		if got := s.Limit(); got != 2 {
			t.Errorf("limit after 30s of statements running 4 times slower = %d; want the floor, 2", got)
		}
		ramp(1)
		if got := s.Limit(); got != 8 {
			t.Errorf("limit after 30s of calm = %d; want back at max_active, 8", got)
		}
		if highest > 8 {
			t.Errorf("limit reached %d; want never above max_active, 8", highest)
		}
	})
}

func TestLoweredLimitHoldsNewStatements(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		limit := newLimit(4)
		s := New(Config{Fast: Lane{MaxActive: 4, QueueTimeout: time.Hour}, Controller: limit})
		go s.Run(t.Context())
		release := acquire(t, s, "a", Fast)
		acquire(t, s, "a", Fast)
		limit.Store(2)
		nextInterval()

		got := make(chan struct{})
		go func() {
			acquire(t, s, "b", Fast)
			close(got)
		}()
		synctest.Wait()
		select {
		case <-got:
			t.Fatal("a third statement ran under a limit of 2")
		default:
		}
		release()
		synctest.Wait()
		select {
		case <-got:
		default:
			t.Error("the waiter did not get the slot freed under the limit")
		}
	})
}

func TestLimitNeverPassesMaxActive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		limit := newLimit(100)
		s := New(Config{Fast: Lane{MaxActive: 4}, Controller: limit})
		go s.Run(t.Context())
		nextInterval()
		if got := s.Limit(); got != 4 {
			t.Errorf("limit = %d; want max_active, 4", got)
		}
		limit.Store(0)
		nextInterval()
		if got := s.Limit(); got != 1 {
			t.Errorf("limit = %d; want 1, the least that runs anything", got)
		}
	})
}

func TestHigherPriorityGetsSlotsFirst(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Fast: Lane{MaxActive: 1, QueueTimeout: time.Minute}})
		// light has used least, so only priority puts the others ahead of it.
		s.Charge("best", 100)
		s.Charge("crit", 100)
		release := acquire(t, s, "x", Fast)

		var mu sync.Mutex
		var order []string
		var wg sync.WaitGroup
		for tenant, prio := range map[string]Priority{"best": BestEffort, "light": Normal, "crit": Critical} {
			wg.Go(func() {
				done, err := s.Acquire(t.Context(), tenant, Fast, prio)
				if err != nil {
					t.Errorf("Acquire(%s) = %v", tenant, err)
					return
				}
				mu.Lock()
				order = append(order, tenant)
				mu.Unlock()
				done()
			})
			synctest.Wait()
		}
		release()
		wg.Wait()

		if !slices.Equal(order, []string{"crit", "light", "best"}) {
			t.Errorf("slots went to %v; want crit, light, best", order)
		}
	})
}

func TestBestEffortIsShedUnderOverload(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		limit := newLimit(2)
		s := New(Config{Fast: Lane{MaxActive: 2, QueueTimeout: time.Hour}, Controller: limit})
		go s.Run(t.Context())
		release := acquire(t, s, "a", Fast)
		acquire(t, s, "a", Fast)
		queued := make(chan error, 1)
		go func() {
			_, err := s.Acquire(t.Context(), "batch", Fast, BestEffort)
			queued <- err
		}()
		normal := make(chan error, 1)
		go func() {
			_, err := s.Acquire(t.Context(), "app", Fast, Normal)
			normal <- err
		}()
		synctest.Wait()

		limit.Store(1)
		nextInterval()

		// A lowered limit means overload: waiting best-effort statements are shed, and new ones that would wait too.
		if err := <-queued; !errors.Is(err, ErrShed) {
			t.Errorf("queued best-effort statement = %v; want ErrShed", err)
		}
		if _, err := s.Acquire(t.Context(), "batch", Fast, BestEffort); !errors.Is(err, ErrShed) {
			t.Errorf("new best-effort statement = %v; want ErrShed", err)
		}
		release()
		synctest.Wait()
		select {
		case err := <-normal:
			t.Errorf("normal statement ran under a limit of 1 with 1 running: %v", err)
		default:
		}

		// Once the limit grows again, best-effort statements wait their turn as before.
		limit.Store(2)
		nextInterval()
		if err := <-normal; err != nil {
			t.Errorf("normal statement = %v; want it to keep waiting until a slot came free", err)
		}
	})
}

func TestRemovingTheControllerEndsShedding(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		limit := newLimit(1)
		s := New(Config{Fast: Lane{MaxActive: 2, QueueTimeout: time.Second}, Controller: limit})
		go s.Run(t.Context())
		nextInterval()

		s.Configure(Config{Fast: Lane{MaxActive: 2, QueueTimeout: time.Second}})
		acquire(t, s, "a", Fast)
		acquire(t, s, "a", Fast)

		if _, err := s.Acquire(t.Context(), "batch", Fast, BestEffort); !errors.Is(err, ErrBusy) {
			t.Errorf("best-effort statement = %v; want it to wait its turn and time out, as with no controller", err)
		}
	})
}

func TestShedAsTheWaitEndsFreesNoSlot(t *testing.T) {
	// The shed and the timeout land at the same instant, and select picks either, so this runs often enough to see both.
	for range 50 {
		synctest.Test(t, func(t *testing.T) {
			limit := newLimit(2)
			s := New(Config{Fast: Lane{MaxActive: 2, QueueTimeout: AdjustInterval}, Controller: limit})
			go s.Run(t.Context())
			release := acquire(t, s, "a", Fast)
			acquire(t, s, "a", Fast)
			limit.Store(1)

			if _, err := s.Acquire(t.Context(), "batch", Fast, BestEffort); err == nil {
				t.Fatal("best-effort statement got a slot under overload")
			}
			synctest.Wait()
			release()
			if _, err := s.Acquire(t.Context(), "app", Fast, Normal); !errors.Is(err, ErrBusy) {
				t.Fatalf("normal statement with 1 running under a limit of 1 = %v; want ErrBusy", err)
			}
		})
	}
}

func TestHeldBestEffortWaitsUntilReleased(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Fast: Lane{MaxActive: 4, QueueTimeout: time.Minute}})
		s.HoldBestEffort(true)
		got := make(chan error, 1)
		go func() {
			_, err := s.Acquire(t.Context(), "batch", Fast, BestEffort)
			got <- err
		}()
		synctest.Wait()
		select {
		case err := <-got:
			t.Fatalf("held best-effort statement ran at once: %v", err)
		default:
		}
		// Others run as usual.
		acquire(t, s, "app", Fast)

		s.HoldBestEffort(false)

		if err := <-got; err != nil {
			t.Errorf("best-effort statement after the hold = %v", err)
		}
	})
}

func TestHeldBestEffortGivesUpWithErrHeld(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Fast: Lane{MaxActive: 4, QueueTimeout: time.Second}})
		s.HoldBestEffort(true)

		if _, err := s.Acquire(t.Context(), "batch", Fast, BestEffort); !errors.Is(err, ErrHeld) {
			t.Errorf("held best-effort statement = %v; want ErrHeld after the queue timeout", err)
		}
	})
}

func TestCappedTenantRunsOneAtATime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Fast: Lane{MaxActive: 3, QueueTimeout: time.Minute}})
		s.CapTenant("analytics", 1)
		release := acquire(t, s, "analytics", Fast)
		got := make(chan struct{})
		go func() {
			acquire(t, s, "analytics", Fast)
			close(got)
		}()
		synctest.Wait()
		select {
		case <-got:
			t.Fatal("a capped tenant ran two statements at once")
		default:
		}
		// The capped tenant's waiting statement holds no one else up.
		acquire(t, s, "app", Fast)

		release()
		synctest.Wait()
		select {
		case <-got:
		default:
			t.Error("the capped tenant's next statement did not run once its first ended")
		}
	})
}

func TestUncappingLetsWaitersRun(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Fast: Lane{MaxActive: 3, QueueTimeout: time.Minute}})
		s.CapTenant("analytics", 1)
		acquire(t, s, "analytics", Fast)
		got := make(chan struct{})
		go func() {
			acquire(t, s, "analytics", Fast)
			close(got)
		}()
		synctest.Wait()

		s.CapTenant("analytics", 0)

		synctest.Wait()
		select {
		case <-got:
		default:
			t.Error("lifting the cap left a statement waiting with slots free")
		}
	})
}

func TestLongStatementMovesToTheSlowLane(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Fast: Lane{MaxActive: 1, QueueTimeout: time.Minute}, Slow: Lane{MaxActive: 1, QueueTimeout: time.Minute}, DemoteAfter: 5 * time.Second})
		long := acquire(t, s, "a", Fast)
		time.Sleep(5 * time.Second)
		synctest.Wait()

		// The long statement now counts in the slow lane, so the fast lane has its slot back and the slow lane is full.
		acquire(t, s, "b", Fast)
		got := make(chan struct{})
		go func() {
			acquire(t, s, "c", Slow)
			close(got)
		}()
		synctest.Wait()
		select {
		case <-got:
			t.Fatal("the slow lane ran a second statement beside the demoted one")
		default:
		}
		long()
		synctest.Wait()
		select {
		case <-got:
		default:
			t.Error("ending the demoted statement freed no slow slot")
		}
	})
}

func TestTrueUpChargesTheDifference(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Budgets: map[string]Budget{"acme": {Rate: 1, Burst: 100, WhenOver: Reject}}})
		s.Charge("acme", 50)

		s.TrueUp("acme", 50, 150)
		if !s.Spent("acme") {
			t.Error("a statement that cost 150, not the 50 charged, left the budget unspent")
		}
		s.TrueUp("acme", 150, 10)
		if s.Spent("acme") {
			t.Error("a statement that cost 10, not 150, left the budget spent")
		}
	})
}

func TestStandingQueueServesNewestFirst(t *testing.T) {
	for wait, want := range map[time.Duration]string{500 * time.Millisecond: "first", 2 * time.Second: "second"} {
		synctest.Test(t, func(t *testing.T) {
			s := New(Config{Fast: Lane{MaxActive: 1, QueueTimeout: time.Minute, StandingAfter: time.Second, StandingTimeout: time.Minute}})
			release := acquire(t, s, "x", Fast)
			got := make(chan string, 2)
			for _, name := range []string{"first", "second"} {
				go func() {
					done := acquire(t, s, "a", Fast)
					got <- name
					done()
				}()
				synctest.Wait()
				time.Sleep(wait / 2)
			}

			release()

			// A queue that hasn't emptied for a second stands, and then the newest waiter, whose client is likeliest still there, goes first.
			if first := <-got; first != want {
				t.Errorf("after the queue stood %v, %s went first; want %s", wait, first, want)
			}
			<-got
		})
	}
}

func TestStandingQueueDropsWaitersPastItsTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Fast: Lane{MaxActive: 1, QueueTimeout: time.Minute, StandingAfter: time.Second, StandingTimeout: 500 * time.Millisecond}})
		release := acquire(t, s, "x", Fast)
		old := make(chan error, 1)
		go func() {
			_, err := s.Acquire(t.Context(), "a", Fast, Normal)
			old <- err
		}()
		synctest.Wait()
		time.Sleep(1900 * time.Millisecond)
		recent := make(chan error, 1)
		go func() {
			done, err := s.Acquire(t.Context(), "b", Fast, Normal)
			if done != nil {
				done()
			}
			recent <- err
		}()
		synctest.Wait()
		time.Sleep(100 * time.Millisecond)

		release()

		if err := <-old; !errors.Is(err, ErrBusy) {
			t.Errorf("waiter queued 2s in a standing queue = %v; want ErrBusy", err)
		}
		if err := <-recent; err != nil {
			t.Errorf("waiter queued 100ms = %v; want the slot", err)
		}
	})
}

func TestNewArrivalAtAStandingQueueWaitsBriefly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Fast: Lane{MaxActive: 1, QueueTimeout: time.Minute, StandingAfter: time.Second, StandingTimeout: 500 * time.Millisecond}})
		acquire(t, s, "x", Fast)
		go s.Acquire(t.Context(), "a", Fast, Normal)
		synctest.Wait()
		time.Sleep(2 * time.Second)

		start := time.Now()
		_, err := s.Acquire(t.Context(), "b", Fast, Normal)

		if !errors.Is(err, ErrBusy) || time.Since(start) != 500*time.Millisecond {
			t.Errorf("arrival at a standing queue = %v after %v; want ErrBusy after 500ms", err, time.Since(start))
		}
	})
}

func TestAcquireWithAnEndedContextTakesNoSlot(t *testing.T) {
	s := New(Config{Fast: Lane{MaxActive: 1}})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := s.Acquire(ctx, "a", Fast, Normal); !errors.Is(err, context.Canceled) {
		t.Errorf("Acquire with an ended context = %v; want its error", err)
	}
	acquire(t, s, "b", Fast)
}

func TestShutLaneRunsNothingUntilItOpens(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Fast: Lane{MaxActive: -1, QueueTimeout: time.Minute}})
		got := make(chan error, 1)
		go func() {
			_, err := s.Acquire(t.Context(), "a", Fast, Normal)
			got <- err
		}()
		synctest.Wait()
		select {
		case err := <-got:
			t.Fatalf("a shut lane ran a statement: %v", err)
		default:
		}

		s.Configure(Config{Fast: Lane{MaxActive: 2, QueueTimeout: time.Minute}})

		if err := <-got; err != nil {
			t.Errorf("statement once the lane opened = %v", err)
		}
	})
}

func TestAdaptiveLimitStartsOverWhenTheLaneOpens(t *testing.T) {
	s := New(Config{Fast: Lane{MaxActive: -1}, Controller: AIMD{}})
	s.Configure(Config{Fast: Lane{MaxActive: 4}, Controller: AIMD{}})
	if got := s.Limit(); got != 4 {
		t.Errorf("limit after the lane opened = %d; want 4", got)
	}
}

func TestShutBudgetWaitsForCapacity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		shut := Config{Fast: Lane{QueueTimeout: time.Second}, Budgets: map[string]Budget{"acme": {Rate: -1, WhenOver: Reject}}}
		s := New(shut)
		start := time.Now()
		if _, err := s.Reserve(t.Context(), "acme"); !errors.Is(err, ErrOverBudget) || time.Since(start) != time.Second {
			t.Errorf("Reserve on a shut budget = %v after %v; want ErrOverBudget after the queue timeout", err, time.Since(start))
		}

		got := make(chan error, 1)
		go func() {
			_, err := s.Reserve(t.Context(), "acme")
			got <- err
		}()
		time.Sleep(300 * time.Millisecond)
		s.Configure(Config{Fast: Lane{QueueTimeout: time.Second}, Budgets: map[string]Budget{"acme": {Rate: 100, WhenOver: Reject}}})

		if err := <-got; err != nil {
			t.Errorf("Reserve once the budget opened = %v", err)
		}
	})
}

func TestTakeDemand(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(Config{Fast: Lane{MaxActive: 2, QueueTimeout: time.Second}, Budgets: map[string]Budget{"tight": {Rate: 1, Burst: 1, WhenOver: Reject}}})
		s.Charge("acme", 30)
		s.Charge("acme", 20)
		s.Charge("tight", 5)
		s.Reserve(t.Context(), "tight")
		acquire(t, s, "a", Fast)
		acquire(t, s, "a", Fast)
		go s.Acquire(t.Context(), "a", Fast, Normal)
		synctest.Wait()

		d := s.TakeDemand()

		if d.Spent["acme"] != 50 || d.Spent["tight"] != 5 || !d.Starved["tight"] || d.Starved["acme"] {
			t.Errorf("demand %+v; want 50 spent by acme, 5 by tight, which was starved", d)
		}
		// Two running and one waiting.
		if d.Slots[Fast] != 3 {
			t.Errorf("fast lane demand %d; want 3", d.Slots[Fast])
		}
		if again := s.TakeDemand(); len(again.Spent) != 0 || len(again.Starved) != 0 || again.Slots[Fast] != 3 {
			t.Errorf("second TakeDemand = %+v; want nothing spent and the slots still in use", again)
		}
	})
}

// nextInterval waits until Run has adjusted the limit once more.
func nextInterval() {
	time.Sleep(AdjustInterval)
	synctest.Wait()
}

// setLimit is a Controller that sets the limit to the number it holds.
type setLimit struct{ atomic.Int64 }

func (n *setLimit) Adjust(int, Signal) int { return int(n.Load()) }

func newLimit(n int) *setLimit {
	l := &setLimit{}
	l.Store(int64(n))
	return l
}

func reserve(t *testing.T, s *Scheduler, tenant string, want LaneID) {
	t.Helper()
	got, err := s.Reserve(t.Context(), tenant)
	if err != nil || got != want {
		t.Fatalf("Reserve(%s) = %v, %v; want %v", tenant, got, err, want)
	}
}

func acquire(t *testing.T, s *Scheduler, tenant string, lane LaneID) func() {
	t.Helper()
	release, err := s.Acquire(t.Context(), tenant, lane, Normal)
	if err != nil {
		t.Errorf("Acquire(%s) = %v", tenant, err)
		return func() {}
	}
	return release
}
