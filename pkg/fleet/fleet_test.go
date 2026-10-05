package fleet

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestFirstLeaseGivesTheWholeCapacity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &Fleet{Store: &Memory{}, Name: "a"}
		if got := f.Share("rate:acme"); got != 0 {
			t.Errorf("share before any lease = %v; want 0", got)
		}
		go f.Run(t.Context(), wanting(100, 10), nil)

		time.Sleep(DefaultInterval + time.Millisecond)

		if got := f.Share("rate:acme"); got != 100 {
			t.Errorf("share = %v; want all 100", got)
		}
	})
}

func TestCapacityFollowsDemand(t *testing.T) {
	for name, tc := range map[string]struct{ a, b, wantA, wantB float64 }{
		"equal demand":                   {50, 50, 50, 50},
		"busier instance":                {90, 10, 90, 10},
		"spare spread evenly":            {10, 30, 40, 60},
		"over capacity, by demand":       {300, 100, 75, 25},
		"no demand at all, split evenly": {0, 0, 50, 50},
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				store := &Memory{}
				a, b := &Fleet{Store: store, Name: "a"}, &Fleet{Store: store, Name: "b"}
				go a.Run(t.Context(), wanting(100, tc.a), nil)
				go b.Run(t.Context(), wanting(100, tc.b), nil)

				time.Sleep(5*DefaultInterval + time.Millisecond)

				if ga, gb := a.Share("rate:acme"), b.Share("rate:acme"); math.Abs(ga-tc.wantA) > 1e-6 || math.Abs(gb-tc.wantB) > 1e-6 {
					t.Errorf("shares %v and %v; want %v and %v", ga, gb, tc.wantA, tc.wantB)
				}
			})
		})
	}
}

func TestReleaseHandsCapacityOn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &Memory{}
		a, b := &Fleet{Store: store, Name: "a"}, &Fleet{Store: store, Name: "b"}
		ctx, stopA := context.WithCancel(t.Context())
		go a.Run(ctx, wanting(100, 50), nil)
		go b.Run(t.Context(), wanting(100, 50), nil)
		time.Sleep(3 * DefaultInterval)

		stopA()
		if err := a.Release(t.Context()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * DefaultInterval)

		if got := b.Share("rate:acme"); got != 100 {
			t.Errorf("share after the other instance left = %v; want all 100", got)
		}
	})
}

func TestLostStoreKeepsWhatFitsTheFallbackShareThenNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &faulty{Store: &Memory{}}
		f := &Fleet{Store: store, Name: "a", MaxInstances: 4}
		go f.Run(t.Context(), wanting(100, 100), nil)
		time.Sleep(2 * DefaultInterval)
		store.down.Store(true)

		time.Sleep(DefaultTTL + time.Second)
		if got := f.Share("rate:acme"); got != 25 {
			t.Errorf("share once the lease ran out = %v; want its 100 cut to the fallback share, 100/4", got)
		}
		time.Sleep(DefaultDeadAfter)
		if got := f.Share("rate:acme"); got != 0 {
			t.Errorf("share past dead_after = %v; want 0, since the store may have given its share away", got)
		}
		store.down.Store(false)
		time.Sleep(2 * DefaultInterval)
		if got := f.Share("rate:acme"); got != 100 {
			t.Errorf("share once the store is back = %v; want 100", got)
		}
	})
}

func TestInstancesGetDistinctIDsAndKnowEachOther(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &Memory{}
		a, b := &Fleet{Store: store, Name: "a", Addr: "10.0.0.1:6543"}, &Fleet{Store: store, Name: "b", Addr: "10.0.0.2:6543"}
		go a.Run(t.Context(), wanting(100, 1), nil)
		go b.Run(t.Context(), wanting(100, 1), nil)
		time.Sleep(2*DefaultInterval + time.Millisecond)

		if a.ID() == 0 || b.ID() == 0 || a.ID() == b.ID() {
			t.Fatalf("ids %d and %d; want two distinct ones", a.ID(), b.ID())
		}
		if addr, ok := a.Peer(b.ID()); !ok || addr != "10.0.0.2:6543" {
			t.Errorf("a's peer %d is %q, %v; want b's address", b.ID(), addr, ok)
		}
	})
}

// TestNeverMoreThanTheTotal runs instances through store outages, cut links, slow and lost replies and deaths, checking every 50ms
// that the shares they use add up to no more than the capacity.
func TestNeverMoreThanTheTotal(t *testing.T) {
	for seed := range uint64(20) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := rand.New(rand.NewPCG(seed, 1))
				memory := &Memory{}
				const capacity, instances = 1000.0, 4
				var fleets []*Fleet
				var links []*faulty
				var stops []context.CancelFunc
				var demands []*atomic.Int64
				var outage atomic.Bool
				quit := make(chan struct{})
				var running sync.WaitGroup
				defer func() {
					for _, stop := range stops {
						stop()
					}
					close(quit)
					running.Wait()
				}()
				for i := range instances {
					link := &faulty{Store: memory, r: rand.New(rand.NewPCG(seed, uint64(i+2))), global: &outage, quit: quit}
					f := &Fleet{Store: link, Name: fmt.Sprint(i), MaxInstances: instances}
					demand := &atomic.Int64{}
					demand.Store(int64(r.IntN(1000)))
					ctx, stop := context.WithCancel(t.Context())
					running.Go(func() {
						f.Run(ctx, func() map[string]Want {
							return map[string]Want{"rate:acme": {Capacity: capacity, Demand: float64(demand.Load())}}
						}, nil)
					})
					fleets, links, stops, demands = append(fleets, f), append(links, link), append(stops, stop), append(demands, demand)
				}

				for step := range 3000 {
					time.Sleep(50 * time.Millisecond)
					var total float64
					for _, f := range fleets {
						total += f.Share("rate:acme")
					}
					if total > capacity+1e-6 {
						t.Fatalf("step %d: instances use %v of %v", step, total, capacity)
					}
					switch n := r.IntN(400); {
					case n < 4:
						demands[n].Store(int64(r.IntN(2000)))
					case n == 4:
						outage.Store(!outage.Load())
					case n < 9:
						links[n-5].cut.Store(!links[n-5].cut.Load())
					case n < 13:
						links[n-9].slow.Store(!links[n-9].slow.Load())
					case n < 17:
						links[n-13].lossy.Store(!links[n-13].lossy.Load())
					case n == 17:
						// An instance dies, and a new one takes its place.
						i := r.IntN(instances)
						stops[i]()
						link := &faulty{Store: memory, r: rand.New(rand.NewPCG(seed, uint64(step))), global: &outage, quit: quit}
						f := &Fleet{Store: link, Name: fmt.Sprint("new", step), MaxInstances: instances}
						ctx, stop := context.WithCancel(t.Context())
						demand := demands[i]
						running.Go(func() {
							f.Run(ctx, func() map[string]Want {
								return map[string]Want{"rate:acme": {Capacity: capacity, Demand: float64(demand.Load())}}
							}, nil)
						})
						// The dead one uses nothing from now on, so it leaves the sum.
						fleets[i], links[i], stops[i] = f, link, stop
					}
				}
			})
		})
	}
}

// wanting asks for one resource, rate:acme, with the given capacity and demand.
func wanting(capacity, demand float64) func() map[string]Want {
	return func() map[string]Want { return map[string]Want{"rate:acme": {Capacity: capacity, Demand: demand}} }
}

// faulty is a Store whose link can be down, cut, slow or lose replies.
type faulty struct {
	Store
	r      *rand.Rand
	mu     sync.Mutex
	global *atomic.Bool  // the store itself is down for everyone
	down   atomic.Bool   // this link is down
	cut    atomic.Bool   // requests never arrive
	slow   atomic.Bool   // requests and replies take seconds each way
	lossy  atomic.Bool   // the store acts on requests but the replies are lost
	quit   chan struct{} // closed when the test ends, cutting delays short
}

var errDown = errors.New("store unreachable")

func (s *faulty) Refresh(ctx context.Context, req Request) (Reply, error) {
	if s.down.Load() || s.cut.Load() || (s.global != nil && s.global.Load()) {
		return Reply{}, errDown
	}
	if s.slow.Load() {
		s.wait()
	}
	reply, err := s.Store.Refresh(context.WithoutCancel(ctx), req)
	if s.slow.Load() {
		s.wait()
	}
	if err == nil && s.lossy.Load() {
		return Reply{}, errDown
	}
	if ctx.Err() != nil {
		return Reply{}, ctx.Err()
	}
	return reply, err
}

// wait sleeps for a random time up to 8s, or until the test ends.
func (s *faulty) wait() {
	s.mu.Lock()
	d := 3 * time.Second
	if s.r != nil {
		d = time.Duration(s.r.IntN(8000)) * time.Millisecond
	}
	s.mu.Unlock()
	select {
	case <-time.After(d):
	case <-s.quit:
	}
}
