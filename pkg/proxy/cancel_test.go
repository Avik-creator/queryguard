package proxy

import (
	"bytes"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

func TestCancelKeyHasServerKeyLength(t *testing.T) {
	for _, n := range []int{4, 32, 256} {
		var keys cancelKeys
		server := &pgproto3.BackendKeyData{ProcessID: 4242, SecretKey: bytes.Repeat([]byte{7}, n)}

		issued, _ := keys.issue(server, 0)

		if len(issued.SecretKey) != n {
			t.Errorf("issued a %d-byte key for a %d-byte server key", len(issued.SecretKey), n)
		}
		if bytes.Equal(issued.SecretKey, server.SecretKey) {
			t.Errorf("issued the server's own %d-byte key", n)
		}
	}
}

func TestCancelKeyLeadsToServerKey(t *testing.T) {
	var keys cancelKeys
	server := &pgproto3.BackendKeyData{ProcessID: 4242, SecretKey: bytes.Repeat([]byte{7}, 32)}
	issued, _ := keys.issue(server, 0)

	req, ok := keys.lookup(&pgproto3.CancelRequest{ProcessID: issued.ProcessID, SecretKey: issued.SecretKey})

	if !ok || req.ProcessID != 4242 || !bytes.Equal(req.SecretKey, server.SecretKey) {
		t.Fatalf("got %+v, %v; want the server's process 4242 and key", req, ok)
	}
}

func TestCancelKeyRejectsWrongSecret(t *testing.T) {
	var keys cancelKeys
	issued, _ := keys.issue(&pgproto3.BackendKeyData{ProcessID: 4242, SecretKey: bytes.Repeat([]byte{7}, 32)}, 0)
	for name, secret := range map[string][]byte{
		"one byte off": append(bytes.Clone(issued.SecretKey[:31]), issued.SecretKey[31]^1),
		"truncated":    issued.SecretKey[:4],
		"server's key": bytes.Repeat([]byte{7}, 32),
	} {
		if _, ok := keys.lookup(&pgproto3.CancelRequest{ProcessID: issued.ProcessID, SecretKey: secret}); ok {
			t.Errorf("%s: lookup succeeded; want it refused", name)
		}
	}
}

func TestCancelKeyForgottenWhenSessionEnds(t *testing.T) {
	var keys cancelKeys
	issued, forget := keys.issue(&pgproto3.BackendKeyData{ProcessID: 4242, SecretKey: []byte{1, 2, 3, 4}}, 0)

	forget()

	if _, ok := keys.lookup(&pgproto3.CancelRequest{ProcessID: issued.ProcessID, SecretKey: issued.SecretKey}); ok {
		t.Fatal("lookup succeeded after forget; want it refused")
	}
}

func TestCancelKeyCarriesTheInstanceID(t *testing.T) {
	var keys cancelKeys
	for range 100 {
		issued, _ := keys.issue(&pgproto3.BackendKeyData{ProcessID: 4242, SecretKey: bytes.Repeat([]byte{7}, 4)}, 5)
		if owner(issued.ProcessID) != 5 || issued.ProcessID&(1<<instanceShift-1) == 0 {
			t.Fatalf("issued process ID %#x; want instance 5 in its top bits and the rest not all zero", issued.ProcessID)
		}
	}
}
