package proxy

import (
	"maps"
	"net/netip"
	"sync"
	"time"

	"github.com/Avik-creator/queryguard/pkg/policy"
	"github.com/Avik-creator/queryguard/pkg/session"
)

// sessionCount counts open sessions, in total and per role, for the connection caps.
type sessionCount struct {
	mu     sync.Mutex
	total  int
	byRole map[string]int
}

// add counts a session for role unless that would pass maxTotal or maxRole (0 means no cap); release uncounts it.
func (c *sessionCount) add(role string, maxTotal, maxRole int) (release func(), ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if (maxTotal > 0 && c.total >= maxTotal) || (maxRole > 0 && c.byRole[role] >= maxRole) {
		return nil, false
	}
	if c.byRole == nil {
		c.byRole = map[string]int{}
	}
	c.total++
	c.byRole[role]++
	return sync.OnceFunc(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.total--
		if c.byRole[role]--; c.byRole[role] == 0 {
			delete(c.byRole, role)
		}
	}), true
}

// backends knows what each session's server connection runs, by its Postgres process ID, for the checks on the whole server.
type backends struct {
	mu    sync.Mutex
	byPID map[int32]*backend
}

// backend is what one session's server connection runs; it is the session's policy.Backend.
type backend struct {
	mu        sync.Mutex
	tenant    string                          // of the statement it runs, or last ran
	ddl       bool                            // it runs DDL now
	flagged   bool                            // the DDL guard acted on the statement it runs, so it won't again
	interrupt func(session.Interruption) bool // cancels what it runs; nil until the session starts
	blocking  chan struct{}                   // closed while others wait on its locks; made when first asked for
}

func (b *backend) Running(tenant string, ddl bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tenant, b.ddl, b.flagged = tenant, ddl, false
}

func (b *backend) Blocking() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.blocking == nil {
		b.blocking = make(chan struct{})
	}
	return b.blocking
}

// setBlocking says whether others now wait on its locks.
func (b *backend) setBlocking(on bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	select {
	case <-b.blocking:
		if !on {
			b.blocking = make(chan struct{})
		}
	default:
		if on {
			if b.blocking == nil {
				b.blocking = make(chan struct{})
			}
			close(b.blocking)
		}
	}
}

func (b *backend) setInterrupt(f func(session.Interruption) bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.interrupt = f
}

// state returns the tenant it runs for and whether that is DDL.
func (b *backend) state() (tenant string, ddl bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tenant, b.ddl
}

// flag marks the statement it runs as acted on, reporting false when it already was.
func (b *backend) flag() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	first := !b.flagged
	b.flagged = true
	return first
}

// cancel interrupts what it runs with i, reporting whether anything ran.
func (b *backend) cancel(i session.Interruption) bool {
	b.mu.Lock()
	interrupt := b.interrupt
	b.mu.Unlock()
	return interrupt != nil && interrupt(i)
}

// add files b under pid until forget is called.
func (r *backends) add(pid int32, b *backend) (forget func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byPID == nil {
		r.byPID = map[int32]*backend{}
	}
	r.byPID[pid] = b
	return sync.OnceFunc(func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.byPID[pid] == b {
			delete(r.byPID, pid)
		}
	})
}

// all returns every backend by pid.
func (r *backends) all() map[int32]*backend {
	r.mu.Lock()
	defer r.mu.Unlock()
	return maps.Clone(r.byPID)
}

// get returns the backend with pid, or nil when it is no session of this proxy.
func (r *backends) get(pid int32) *backend {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byPID[pid]
}

// maxThrottled is how many addresses and roles the login throttle remembers; past it, those whose cool-off and window are over go.
const maxThrottled = 10000

// loginThrottle counts failed logins by client address and role.
type loginThrottle struct {
	mu   sync.Mutex
	seen map[throttleKey]*loginFailures
}

// throttleKey is an address and role; keying by role too keeps one misconfigured app behind a NAT from locking out the others.
type throttleKey struct {
	addr netip.Addr
	role string
}

type loginFailures struct {
	count        int
	since        time.Time // the start of the window count is over
	blockedUntil time.Time
}

// coolingOff returns how long k's logins are still refused; 0 when they aren't.
func (l *loginThrottle) coolingOff(k throttleKey, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if f := l.seen[k]; f != nil && now.Before(f.blockedUntil) {
		return f.blockedUntil.Sub(now)
	}
	return 0
}

// failed counts a failed login by k and reports whether it starts a cool-off.
func (l *loginThrottle) failed(k throttleKey, now time.Time, t policy.LoginThrottle) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil {
		l.seen = map[throttleKey]*loginFailures{}
	}
	f := l.seen[k]
	if f == nil {
		if len(l.seen) >= maxThrottled {
			l.forget(now, t)
		}
		f = &loginFailures{since: now}
		l.seen[k] = f
	}
	if now.Sub(f.since) > time.Duration(t.Window) {
		f.count, f.since = 0, now
	}
	f.count++
	if f.count < t.Failures {
		return false
	}
	f.count, f.since, f.blockedUntil = 0, now, now.Add(time.Duration(t.CoolOff))
	return true
}

// succeeded forgets k's failures.
func (l *loginThrottle) succeeded(k throttleKey) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.seen, k)
}

// forget drops entries that no longer refuse or count anything; the caller holds mu.
func (l *loginThrottle) forget(now time.Time, t policy.LoginThrottle) {
	maps.DeleteFunc(l.seen, func(_ throttleKey, f *loginFailures) bool {
		return now.After(f.blockedUntil) && now.Sub(f.since) > time.Duration(t.Window)
	})
}
