// Package fleet shares limits, such as a tenant's budget or the number of statements running, among every QueryGuard instance
// in front of one server, by leasing each instance its share from a store, as YouTube's Doorman does.
package fleet

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"maps"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Defaults used when the matching Fleet field is zero.
const (
	DefaultInterval     = time.Second
	DefaultTTL          = 10 * time.Second
	DefaultDeadAfter    = time.Minute
	DefaultMaxInstances = 4
)

// maxID is the highest instance ID, which fits the 10 bits cancel keys give it.
const maxID = 1023

// Store hands out leases; Memory and Postgres are the two kinds.
type Store interface {
	// Refresh files what req asks for and returns the instance's leases, in one step for the whole fleet.
	Refresh(ctx context.Context, req Request) (Reply, error)
	// Release forgets an instance that no longer uses any of its leases.
	Release(ctx context.Context, instance string) error
}

// Request is one instance's report to the store.
type Request struct {
	Instance     string
	Addr         string // where other instances send it cancel requests
	MaxInstances int
	TTL          time.Duration
	DeadAfter    time.Duration
	Wants        map[string]Want  // by resource
	Applied      map[string]int64 // the sequence number of the lease the instance uses for each resource
}

// Want is an instance's view of one resource.
type Want struct {
	Capacity float64 // the fleet-wide limit
	Demand   float64 // how much of it the instance would use
	Using    float64 // how much of it the instance holds now, as statements still running; it counts until they end
	Whole    bool    // it comes in whole units, as slots do
}

// Reply is the store's answer.
type Reply struct {
	ID     int                // unique among live instances, 1 to 1023; 0 when none was free
	Seq    int64              // the sequence number of these leases
	Grants map[string]float64 // by resource
	Peers  map[int]string     // live instances' addresses by ID
}

// Fleet keeps an instance's leases; it is safe for concurrent use.
type Fleet struct {
	Store        Store
	Name         string        // unique to this process; "" picks a random one
	Addr         string        // where other instances can send this one cancel requests
	MaxInstances int           // the most instances expected; each falls back to this share of a limit without the store
	Interval     time.Duration // how often leases are renewed
	TTL          time.Duration // how long a lease lasts
	DeadAfter    time.Duration // how long after its last renewal an instance may still use its fallback share
	Log          *slog.Logger

	mu       sync.Mutex
	name     string
	reply    Reply
	leases   map[string]held
	capacity map[string]float64 // each resource's capacity, as last wanted
	crowded  bool               // more instances than MaxInstances were live at the last renewal
}

// held is a lease in use.
type held struct {
	grant float64
	seq   int64
	sent  time.Time // when the request that got it went out, which is before the store started it
}

// Run renews the instance's leases every Interval with what wants returns, calling changed (if not nil) after each renewal,
// until ctx ends. It leaves the leases in place: call Release once nothing uses them.
func (f *Fleet) Run(ctx context.Context, wants func() map[string]Want, changed func()) {
	tick := time.Tick(f.interval())
	for {
		f.renew(ctx, wants())
		if changed != nil {
			changed()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
	}
}

// renew asks the store for leases once.
func (f *Fleet) renew(ctx context.Context, wants map[string]Want) {
	f.mu.Lock()
	req := Request{Instance: f.instance(), Addr: f.Addr, MaxInstances: f.maxInstances(), TTL: f.ttl(), DeadAfter: f.deadAfter(),
		Wants: wants, Applied: map[string]int64{}}
	for r, l := range f.leases {
		req.Applied[r] = l.seq
	}
	if f.capacity == nil {
		f.capacity = map[string]float64{}
	}
	for r, w := range wants {
		f.capacity[r] = w.Capacity
	}
	f.mu.Unlock()

	// A reply that comes after the next renewal is due is of no use.
	rctx, cancel := context.WithTimeout(ctx, f.interval())
	defer cancel()
	sent := time.Now()
	reply, err := f.Store.Refresh(rctx, req)
	if err != nil {
		if ctx.Err() == nil {
			cmp.Or(f.Log, slog.Default()).Warn("renew fleet leases", "err", err)
		}
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if crowded := len(reply.Peers) > f.maxInstances(); crowded && !f.crowded {
		// Without the store each falls back to capacity ÷ MaxInstances, so together they could use more than the capacity.
		cmp.Or(f.Log, slog.Default()).Warn("more instances than max_instances share the fleet's limits", "instances", len(reply.Peers),
			"max_instances", f.maxInstances())
	}
	f.crowded = len(reply.Peers) > f.maxInstances()
	f.reply = reply
	if f.leases == nil {
		f.leases = map[string]held{}
	}
	for r, g := range reply.Grants {
		f.leases[r] = held{grant: g, seq: reply.Seq, sent: sent}
	}
}

// Share returns how much of resource the instance may use now: its lease's grant while the lease lasts; then, while the store
// can't be reached, as much of it as fits the fallback share, capacity ÷ MaxInstances, which the store keeps counting for an
// instance it hasn't heard from in DeadAfter; and nothing after that.
func (f *Fleet) Share(resource string) float64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.leases[resource]
	if !ok {
		return 0
	}
	now := time.Now()
	switch {
	case now.Before(l.sent.Add(f.ttl())):
		return l.grant
	case now.Before(l.sent.Add(f.deadAfter())):
		return min(l.grant, f.capacity[resource]/float64(f.maxInstances()))
	}
	return 0
}

// ID returns the instance's ID among the fleet, or 0 before the store gave it one.
func (f *Fleet) ID() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reply.ID
}

// Peer returns the address of the live instance with id, unless it is this instance's own, as during a rolling restart, where
// sending to it would reach only this instance.
func (f *Fleet) Peer(id int) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	addr, ok := f.reply.Peers[id]
	return addr, ok && addr != "" && addr != f.Addr
}

// Release gives up the instance's leases; call it once nothing uses them, as after sessions have drained.
func (f *Fleet) Release(ctx context.Context) error {
	f.mu.Lock()
	name := f.instance()
	f.leases = nil
	f.mu.Unlock()
	return f.Store.Release(ctx, name)
}

// instance returns the instance's name, picking one the first time if none was set; the caller holds mu.
func (f *Fleet) instance() string {
	if f.name == "" {
		f.name = f.Name
		if f.name == "" {
			b := make([]byte, 8)
			rand.Read(b)
			f.name = hex.EncodeToString(b)
		}
	}
	return f.name
}

func (f *Fleet) interval() time.Duration { return cmp.Or(f.Interval, DefaultInterval) }
func (f *Fleet) ttl() time.Duration      { return cmp.Or(f.TTL, DefaultTTL) }
func (f *Fleet) deadAfter() time.Duration {
	return max(cmp.Or(f.DeadAfter, DefaultDeadAfter), f.ttl())
}
func (f *Fleet) maxInstances() int { return cmp.Or(f.MaxInstances, DefaultMaxInstances) }

// state is the whole fleet as the store keeps it.
type state struct {
	seq     int64 // of the last renewal of any instance, so an instance that rejoins never gets a number it used before
	members map[string]*member
	rows    map[string]map[string]*row // by instance, then resource
}

// member is one instance as the store knows it.
type member struct {
	id     int
	addr   string
	deadAt time.Time // when it stops using even its fallback share, if it renewed no more
}

// row is one instance's leases of one resource.
type row struct {
	capacity, demand float64
	using            float64   // as last reported
	usingUntil       time.Time // when what it reported using stops counting, if it renewed no more
	applied          int64     // the sequence number of the lease it last said it uses; 0 for none
	grants           []grant   // leases it may still use: those since applied, and not yet dead
}

// grant is one lease the store handed out.
type grant struct {
	seq     int64
	value   float64
	expires time.Time // when the instance stops using all of it
	deadAt  time.Time // when it stops using even the part that fits the fallback share
}

// refresh files req at now and returns the reply, and the rows of req's instance to keep.
func (st *state) refresh(req Request, now time.Time) Reply {
	if st.members == nil {
		st.members, st.rows = map[string]*member{}, map[string]map[string]*row{}
	}
	for name, m := range st.members {
		if !now.Before(m.deadAt) {
			delete(st.members, name)
			delete(st.rows, name)
		}
	}
	m := st.members[req.Instance]
	if m == nil {
		m = &member{id: st.freeID()}
		st.members[req.Instance] = m
		st.rows[req.Instance] = map[string]*row{}
	}
	// A store that lost its tables numbers from 0 again, and its numbers must still pass those its instances use.
	for _, applied := range req.Applied {
		st.seq = max(st.seq, applied)
	}
	st.seq++
	m.addr, m.deadAt = req.Addr, now.Add(req.DeadAfter)
	reply := Reply{ID: m.id, Seq: st.seq, Grants: map[string]float64{}, Peers: map[int]string{}}
	for _, other := range st.members {
		if other.id != 0 {
			reply.Peers[other.id] = other.addr
		}
	}

	own := st.rows[req.Instance]
	for resource, want := range req.Wants {
		r := own[resource]
		if r == nil {
			r = &row{}
			own[resource] = r
		}
		r.capacity, r.demand, r.using, r.usingUntil = want.Capacity, want.Demand, want.Using, m.deadAt
		if applied := req.Applied[resource]; applied > r.applied {
			r.applied = applied
		}
		fair, spare := st.fairShare(req.Instance, resource, want), want.Capacity-st.others(req.Instance, resource, req.MaxInstances, now)
		if want.Whole {
			// Rounding down alone would leave every instance nothing when there are fewer units than instances.
			fair = math.Round(fair)
			if fair < 1 && want.Demand > 0 {
				fair = 1
			}
			spare = math.Floor(spare + 1e-9)
		}
		g := max(0, min(fair, spare))
		r.grants = append(r.grants, grant{seq: st.seq, value: g, expires: now.Add(req.TTL), deadAt: m.deadAt})
		reply.Grants[resource] = g
	}
	// Resources it no longer wants keep their rows until their leases are dead, asking for nothing more meanwhile.
	for resource, r := range own {
		if _, wanted := req.Wants[resource]; !wanted {
			r.demand, r.using = 0, 0
			if r.counted(now, m, req.MaxInstances) == 0 {
				delete(own, resource)
			}
		}
	}
	return reply
}

// freeID returns the lowest ID no member has, or 0 when all are taken.
func (st *state) freeID() int {
	taken := map[int]bool{}
	for _, m := range st.members {
		taken[m.id] = true
	}
	for id := 1; id <= maxID; id++ {
		if !taken[id] {
			return id
		}
	}
	return 0
}

// fairShare is what instance would get of resource by demand: what it asks plus an even part of what's spare, or a part in
// proportion to its demand when the instances ask for more than there is.
func (st *state) fairShare(instance, resource string, want Want) float64 {
	demand, n := want.Demand, 1
	for name, rows := range st.rows {
		if r := rows[resource]; r != nil && name != instance {
			demand += r.demand
			n++
		}
	}
	if demand <= want.Capacity {
		return want.Demand + (want.Capacity-demand)/float64(n)
	}
	return want.Capacity * want.Demand / demand
}

// others is how much of resource every instance but instance may be using at now.
func (st *state) others(instance, resource string, maxInstances int, now time.Time) float64 {
	var sum float64
	for name, rows := range st.rows {
		if r := rows[resource]; r != nil && name != instance {
			sum += r.counted(now, st.members[name], maxInstances)
		}
	}
	return sum
}

// counted is the most of the resource the instance may be using at now, given that it uses one of the leases since the one it
// last said it uses: that lease's grant while it lasts, and as much of it as fits the fallback share after, until it is dead;
// and at least what it said it holds, until it would have renewed in time to say less.
func (r *row) counted(now time.Time, m *member, maxInstances int) float64 {
	if m == nil {
		return 0
	}
	var live, lapsed, using float64
	r.grants = slices.DeleteFunc(r.grants, func(g grant) bool { return g.seq < r.applied || !now.Before(g.deadAt) })
	for _, g := range r.grants {
		if now.Before(g.expires) {
			live = max(live, g.value)
		} else {
			lapsed = max(lapsed, g.value)
		}
	}
	if now.Before(r.usingUntil) {
		using = r.using
	}
	return max(live, min(lapsed, r.capacity/float64(maxInstances)), using)
}

// Memory is a Store in memory, for one process and for tests; its zero value is ready to use.
type Memory struct {
	mu sync.Mutex
	st state
}

func (s *Memory) Refresh(ctx context.Context, req Request) (Reply, error) {
	if err := ctx.Err(); err != nil {
		return Reply{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reply := s.st.refresh(req, time.Now())
	reply.Grants, reply.Peers = maps.Clone(reply.Grants), maps.Clone(reply.Peers)
	return reply, nil
}

func (s *Memory) Release(ctx context.Context, instance string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.st.members, instance)
	delete(s.st.rows, instance)
	return nil
}

// Postgres is a Store in tables of a database set aside for QueryGuard, so it needs nothing new to run. They are logged tables,
// since a crash or failover that emptied them would let the store hand out again what instances still use.
type Postgres struct {
	DSN string // connection string for a role that may create tables in the database

	mu    sync.Mutex
	conn  *pgx.Conn // opened on first use and again after a failure
	ready bool      // the tables were made over conn
}

// schema makes the store's tables; it runs under the store's lock, since CREATE TABLE IF NOT EXISTS can still collide.
const schema = `
create table if not exists queryguard_fleet (one bool primary key default true check (one), seq bigint not null);
create table if not exists queryguard_members (instance text primary key, id int not null, addr text not null,
	dead_at timestamptz not null);
create table if not exists queryguard_leases (instance text not null, resource text not null, capacity float8 not null,
	demand float8 not null, using_now float8 not null, using_until timestamptz not null, applied bigint not null,
	grants jsonb not null, primary key (instance, resource));
insert into queryguard_fleet values (true, 0) on conflict do nothing`

// lockKey names the advisory lock every change to the store takes, so the whole fleet changes one instance at a time.
const lockKey = 7_165_207_501_143_244_885

// storedGrant is a grant as stored in JSON.
type storedGrant struct {
	Seq     int64     `json:"seq"`
	Value   float64   `json:"value"`
	Expires time.Time `json:"expires"`
	DeadAt  time.Time `json:"dead_at"`
}

func (s *Postgres) Refresh(ctx context.Context, req Request) (Reply, error) {
	var reply Reply
	err := s.locked(ctx, func(tx pgx.Tx) error {
		var now time.Time
		st := state{members: map[string]*member{}, rows: map[string]map[string]*row{}}
		if err := tx.QueryRow(ctx, "select clock_timestamp(), seq from queryguard_fleet").Scan(&now, &st.seq); err != nil {
			return err
		}
		var name string
		var m member
		rows, err := tx.Query(ctx, "select instance, id, addr, dead_at from queryguard_members")
		if err != nil {
			return err
		}
		if _, err := pgx.ForEachRow(rows, []any{&name, &m.id, &m.addr, &m.deadAt}, func() error {
			st.members[name] = &member{id: m.id, addr: m.addr, deadAt: m.deadAt}
			st.rows[name] = map[string]*row{}
			return nil
		}); err != nil {
			return err
		}
		var resource string
		var r row
		var grants []storedGrant
		if rows, err = tx.Query(ctx, `select instance, resource, capacity, demand, using_now, using_until, applied, grants
			from queryguard_leases`); err != nil {
			return err
		}
		if _, err := pgx.ForEachRow(rows, []any{&name, &resource, &r.capacity, &r.demand, &r.using, &r.usingUntil, &r.applied, &grants}, func() error {
			// Leases of an instance that is gone are deleted below.
			if st.rows[name] == nil {
				return nil
			}
			stored := &row{capacity: r.capacity, demand: r.demand, using: r.using, usingUntil: r.usingUntil, applied: r.applied}
			for _, g := range grants {
				stored.grants = append(stored.grants, grant{seq: g.Seq, value: g.Value, expires: g.Expires, deadAt: g.DeadAt})
			}
			st.rows[name][resource] = stored
			return nil
		}); err != nil {
			return err
		}

		reply = st.refresh(req, now)

		b := &pgx.Batch{}
		b.Queue("update queryguard_fleet set seq = $1", st.seq)
		// A nil slice is sent as NULL, which <> all() matches nothing against.
		live := slices.AppendSeq([]string{}, maps.Keys(st.members))
		b.Queue("delete from queryguard_members where instance <> all($1)", live)
		b.Queue("delete from queryguard_leases where instance <> all($1)", live)
		own := st.members[req.Instance]
		b.Queue(`insert into queryguard_members values ($1, $2, $3, $4)
			on conflict (instance) do update set id = excluded.id, addr = excluded.addr, dead_at = excluded.dead_at`,
			req.Instance, own.id, own.addr, own.deadAt)
		b.Queue("delete from queryguard_leases where instance = $1 and resource <> all($2)",
			req.Instance, slices.AppendSeq([]string{}, maps.Keys(st.rows[req.Instance])))
		for resource, r := range st.rows[req.Instance] {
			stored := []storedGrant{}
			for _, g := range r.grants {
				stored = append(stored, storedGrant{Seq: g.seq, Value: g.value, Expires: g.expires, DeadAt: g.deadAt})
			}
			b.Queue(`insert into queryguard_leases values ($1, $2, $3, $4, $5, $6, $7, $8)
				on conflict (instance, resource) do update set capacity = excluded.capacity, demand = excluded.demand,
				using_now = excluded.using_now, using_until = excluded.using_until, applied = excluded.applied, grants = excluded.grants`,
				req.Instance, resource, r.capacity, r.demand, r.using, r.usingUntil, r.applied, stored)
		}
		return tx.SendBatch(ctx, b).Close()
	})
	return reply, err
}

func (s *Postgres) Release(ctx context.Context, instance string) error {
	return s.locked(ctx, func(tx pgx.Tx) error {
		b := &pgx.Batch{}
		b.Queue("delete from queryguard_members where instance = $1", instance)
		b.Queue("delete from queryguard_leases where instance = $1", instance)
		return tx.SendBatch(ctx, b).Close()
	})
}

// locked runs f in a transaction holding the store's lock, making the tables first if they are missing.
func (s *Postgres) locked(ctx context.Context, f func(pgx.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		conn, err := pgx.Connect(ctx, s.DSN)
		if err != nil {
			return err
		}
		s.conn = conn
	}
	err := pgx.BeginFunc(ctx, s.conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "select pg_advisory_xact_lock($1)", int64(lockKey)); err != nil {
			return err
		}
		if !s.ready {
			if _, err := tx.Exec(ctx, schema); err != nil {
				return err
			}
		}
		return f(tx)
	})
	if err != nil {
		// The connection may be broken, or mid-query after a timeout; a new one starts clean.
		s.conn.Close(context.Background())
		s.conn, s.ready = nil, false
		return err
	}
	s.ready = true
	return nil
}
