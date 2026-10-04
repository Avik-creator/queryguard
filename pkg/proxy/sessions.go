package proxy

import "sync"

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
