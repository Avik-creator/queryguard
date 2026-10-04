package sched

import (
	"context"
	"errors"
	"slices"
	"sync"
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
		if _, err := s.Acquire(t.Context(), "b", Fast); !errors.Is(err, ErrBusy) || time.Since(start) != time.Second {
			t.Fatalf("Acquire with no slot = %v after %v; want ErrBusy after 1s", err, time.Since(start))
		}

		release()
		release()
		// Releasing twice frees one slot, not two.
		acquire(t, s, "b", Fast)
		if _, err := s.Acquire(t.Context(), "c", Fast); !errors.Is(err, ErrBusy) {
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

		if _, err := s.Acquire(ctx, "b", Fast); !errors.Is(err, context.Canceled) {
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

func reserve(t *testing.T, s *Scheduler, tenant string, want LaneID) {
	t.Helper()
	got, err := s.Reserve(t.Context(), tenant)
	if err != nil || got != want {
		t.Fatalf("Reserve(%s) = %v, %v; want %v", tenant, got, err, want)
	}
}

func acquire(t *testing.T, s *Scheduler, tenant string, lane LaneID) func() {
	t.Helper()
	release, err := s.Acquire(t.Context(), tenant, lane)
	if err != nil {
		t.Errorf("Acquire(%s) = %v", tenant, err)
		return func() {}
	}
	return release
}
