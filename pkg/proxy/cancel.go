package proxy

import (
	"crypto/rand"
	"crypto/subtle"
	mrand "math/rand/v2"
	"sync"

	"github.com/jackc/pgx/v5/pgproto3"
)

// cancelKeys gives each session cancel key data of its own and remembers the server's real key.
type cancelKeys struct {
	mu       sync.Mutex
	sessions map[uint32]cancelKey // by the process ID the client was given
}

type cancelKey struct {
	secret []byte                   // what the client was given
	server *pgproto3.BackendKeyData // what Postgres expects
}

// issue returns key data for the client, as long as the server's so the negotiated protocol still fits, and a function that forgets it.
func (k *cancelKeys) issue(server *pgproto3.BackendKeyData) (*pgproto3.BackendKeyData, func()) {
	secret := make([]byte, len(server.SecretKey))
	rand.Read(secret)

	k.mu.Lock()
	defer k.mu.Unlock()
	if k.sessions == nil {
		k.sessions = make(map[uint32]cancelKey)
	}
	// Random rather than counted, so IDs don't reveal how many sessions the proxy has served.
	var pid uint32
	for {
		pid = mrand.Uint32()
		if _, taken := k.sessions[pid]; pid != 0 && !taken {
			break
		}
	}
	k.sessions[pid] = cancelKey{secret: secret, server: server}

	forget := func() {
		k.mu.Lock()
		defer k.mu.Unlock()
		delete(k.sessions, pid)
	}
	return &pgproto3.BackendKeyData{ProcessID: pid, SecretKey: secret}, forget
}

// lookup returns the CancelRequest to send to the server, or false if req matches no live session.
func (k *cancelKeys) lookup(req *pgproto3.CancelRequest) (*pgproto3.CancelRequest, bool) {
	k.mu.Lock()
	key, ok := k.sessions[req.ProcessID]
	k.mu.Unlock()
	// Constant time, so response timing can't reveal how much of a guessed key was right.
	if !ok || subtle.ConstantTimeCompare(req.SecretKey, key.secret) != 1 {
		return nil, false
	}
	return &pgproto3.CancelRequest{ProcessID: key.server.ProcessID, SecretKey: key.server.SecretKey}, true
}
