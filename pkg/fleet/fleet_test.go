package fleet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"strings"
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

func TestLeaseRunsOutHereBeforeTheStoreGivesItAway(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &faulty{Store: &Memory{}}
		f := &Fleet{Store: store, Name: "a", MaxInstances: 4}
		go f.Run(t.Context(), wanting(100, 100), nil)
		time.Sleep(1500 * time.Millisecond)
		store.down.Store(true)

		// The last renewal went out at 1s. A share read now is used until the next renewal ends, up to two intervals on, by
		// when the store counts the lease as run out.
		time.Sleep(DefaultTTL - 2*DefaultInterval)
		if got := f.Share("rate:acme"); got != 25 {
			t.Errorf("share two intervals before the store's lease ends = %v; want the fallback share, 100/4", got)
		}
		time.Sleep(DefaultDeadAfter - DefaultTTL)
		if got := f.Share("rate:acme"); got != 0 {
			t.Errorf("share two intervals before the store forgets the instance = %v; want 0", got)
		}
	})
}

func TestFallbackShareIsOfTheCapacityTheStoreGot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &faulty{Store: &Memory{}}
		f := &Fleet{Store: store, Name: "a", MaxInstances: 4}
		var capacity atomic.Int64
		capacity.Store(8)
		go f.Run(t.Context(), func() map[string]Want {
			return map[string]Want{"rate:acme": {Capacity: float64(capacity.Load()), Demand: 100}}
		}, nil)
		time.Sleep(1500 * time.Millisecond)
		store.down.Store(true)
		// The store never hears of the new capacity, so it still counts this instance at 8/4.
		capacity.Store(40)

		time.Sleep(DefaultTTL)
		if got := f.Share("rate:acme"); got != 2 {
			t.Errorf("fallback share = %v; want 2, a quarter of the capacity the store last got", got)
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

func TestPeerAtTheInstancesOwnAddressIsNoPeer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// During a rolling restart the old and new processes share an address; sending there reaches only the new one.
		store := &Memory{}
		old, next := &Fleet{Store: store, Name: "old", Addr: "10.0.0.1:6543"}, &Fleet{Store: store, Name: "next", Addr: "10.0.0.1:6543"}
		go old.Run(t.Context(), wanting(100, 1), nil)
		go next.Run(t.Context(), wanting(100, 1), nil)
		time.Sleep(2*DefaultInterval + time.Millisecond)

		if addr, ok := next.Peer(old.ID()); ok {
			t.Errorf("peer %d is %q; want none, since that address is the instance's own", old.ID(), addr)
		}
	})
}

func TestWarnsWhenMoreInstancesRunThanTheFallbackShareAllowsFor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs lockedBuffer
		store := &Memory{}
		log := slog.New(slog.NewTextHandler(&logs, nil))
		a := &Fleet{Store: store, Name: "a", MaxInstances: 1, Log: log}
		b := &Fleet{Store: store, Name: "b", MaxInstances: 1, Log: log}
		go a.Run(t.Context(), wanting(100, 1), nil)
		go b.Run(t.Context(), wanting(100, 1), nil)

		time.Sleep(3*DefaultInterval + time.Millisecond)

		// Each falls back to capacity ÷ max_instances without the store, so more instances than that could together use more.
		if n := strings.Count(logs.String(), "more instances than max_instances"); n != 2 {
			t.Errorf("warned %d times; want once by each instance:\n%s", n, logs.String())
		}
	})
}

// lockedBuffer is a bytes.Buffer several loggers can write at once.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// ask is instance's request for wants, using the leases in applied.
func ask(instance string, wants map[string]Want, applied map[string]int64) Request {
	return Request{Instance: instance, MaxInstances: DefaultMaxInstances, TTL: DefaultTTL, DeadAfter: DefaultDeadAfter, Wants: wants,
		Applied: applied}
}

func TestStoreThatLostItsTablesStillCountsTheLeasesInUse(t *testing.T) {
	var st state
	now := time.Now()
	want := map[string]Want{"r": {Capacity: 100, Demand: 100}}

	// a used lease 500 before the store's numbering started again; the new numbers must still count as its leases.
	got := st.refresh(ask("a", want, map[string]int64{"r": 500}), now)
	got = st.refresh(ask("a", want, map[string]int64{"r": got.Seq}), now.Add(time.Second))
	b := st.refresh(ask("b", map[string]Want{"r": {Capacity: 100, Demand: 50}}, nil), now.Add(2*time.Second))

	if got.Grants["r"] != 100 || b.Grants["r"] != 0 {
		t.Errorf("a has %v and b got %v; want a's 100 counted, so 0 for b", got.Grants["r"], b.Grants["r"])
	}
}

func TestResourceNoLongerWantedIsFreedOnceItsLeaseIsDead(t *testing.T) {
	var st state
	now := time.Now()
	got := st.refresh(ask("a", map[string]Want{"r": {Capacity: 100, Demand: 100}}, nil), now)
	applied := map[string]int64{"r": got.Seq}

	// a keeps renewing, wanting nothing more of r, as when its tenant was forgotten.
	for at := time.Second; at <= DefaultDeadAfter+time.Second; at += time.Second {
		st.refresh(ask("a", nil, applied), now.Add(at))
	}
	b := st.refresh(ask("b", map[string]Want{"r": {Capacity: 100, Demand: 50}}, nil), now.Add(DefaultDeadAfter+2*time.Second))

	if b.Grants["r"] != 100 {
		t.Errorf("b got %v; want all 100, since a's lease of r is dead", b.Grants["r"])
	}
}

func TestWholeResourcesAreLeasedInWholeUnits(t *testing.T) {
	var st state
	now := time.Now()
	applied := map[string]map[string]int64{}
	var grants map[string]float64
	for round := range 5 {
		grants = map[string]float64{}
		for i, name := range []string{"a", "b", "c"} {
			got := st.refresh(ask(name, map[string]Want{"slots": {Capacity: 2, Demand: 1, Whole: true}}, applied[name]),
				now.Add(time.Duration(3*round+i)*time.Second))
			applied[name] = map[string]int64{"slots": got.Seq}
			grants[name] = got.Grants["slots"]
		}
	}

	// Two slots among three instances can't be split evenly; two get one each, rather than all getting none.
	var sum float64
	ones := 0
	for name, g := range grants {
		if g != math.Trunc(g) {
			t.Errorf("%s got %v; want a whole number", name, g)
		}
		sum += g
		if g == 1 {
			ones++
		}
	}
	if sum > 2 || ones != 2 {
		t.Errorf("grants %v; want two instances with one slot each", grants)
	}
}

func TestStatementsStillRunningCountAfterALeaseShrinks(t *testing.T) {
	var st state
	now := time.Now()
	slots := func(demand, using float64) map[string]Want {
		return map[string]Want{"slots": {Capacity: 10, Demand: demand, Using: using, Whole: true}}
	}
	a := st.refresh(ask("a", slots(10, 0), nil), now)
	st.refresh(ask("b", slots(0, 0), nil), now.Add(time.Second/2))
	a = st.refresh(ask("a", slots(10, 10), map[string]int64{"slots": a.Seq}), now.Add(time.Second))
	// a's statements end only when they end, though its demand dropped and it took a smaller lease.
	a = st.refresh(ask("a", slots(0, 10), map[string]int64{"slots": a.Seq}), now.Add(2*time.Second))
	a = st.refresh(ask("a", slots(0, 10), map[string]int64{"slots": a.Seq}), now.Add(3*time.Second))
	b := st.refresh(ask("b", slots(10, 0), nil), now.Add(4*time.Second))

	if a.Grants["slots"] >= 10 || b.Grants["slots"] != 0 {
		t.Errorf("a's lease %v, b got %v; want a's lease cut and b given nothing while a's 10 statements run", a.Grants["slots"], b.Grants["slots"])
	}
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
