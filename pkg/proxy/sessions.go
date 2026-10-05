package proxy

import (
	"sync"

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
}

func (b *backend) Running(tenant string, ddl bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tenant, b.ddl, b.flagged = tenant, ddl, false
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

// get returns the backend with pid, or nil when it is no session of this proxy.
func (r *backends) get(pid int32) *backend {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byPID[pid]
}
