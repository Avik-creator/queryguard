package wire

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

func TestRelayStartupRemovesChannelBindingMechanisms(t *testing.T) {
	server := bytes.NewReader(concat(
		encode(t, &pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"}}),
		encode(t, &pgproto3.ReadyForQuery{TxStatus: 'I'}),
	))
	var client bytes.Buffer

	if err := RelayStartup(&client, server, StartupOptions{}); err != nil {
		t.Fatal(err)
	}

	msg, err := pgproto3.NewFrontend(&client, io.Discard).Receive()
	if err != nil {
		t.Fatal(err)
	}
	if sasl := mustBe[*pgproto3.AuthenticationSASL](t, msg); !slices.Equal(sasl.AuthMechanisms, []string{"SCRAM-SHA-256"}) {
		t.Errorf("client was offered %q; want only SCRAM-SHA-256", sasl.AuthMechanisms)
	}
}

func TestRelayStartupKeepsChannelBindingWhenAllowed(t *testing.T) {
	want := concat(
		encode(t, &pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"}}),
		encode(t, &pgproto3.ReadyForQuery{TxStatus: 'I'}),
	)
	var client bytes.Buffer

	if err := RelayStartup(&client, bytes.NewReader(want), StartupOptions{ChannelBinding: true}); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(client.Bytes(), want) {
		t.Fatalf("client got %q; want %q", client.Bytes(), want)
	}
}

func TestRelayStartupReplacesBackendKeyData(t *testing.T) {
	serverKey := &pgproto3.BackendKeyData{ProcessID: 4242, SecretKey: bytes.Repeat([]byte{7}, 32)}
	proxyKey := &pgproto3.BackendKeyData{ProcessID: 99, SecretKey: bytes.Repeat([]byte{1}, 32)}
	server := bytes.NewReader(concat(
		encode(t, &pgproto3.AuthenticationOk{}),
		encode(t, serverKey),
		encode(t, &pgproto3.ReadyForQuery{TxStatus: 'I'}),
	))
	var client bytes.Buffer
	var got *pgproto3.BackendKeyData

	err := RelayStartup(&client, server, StartupOptions{IssueKey: func(k *pgproto3.BackendKeyData) *pgproto3.BackendKeyData {
		got = k
		return proxyKey
	}})
	if err != nil {
		t.Fatal(err)
	}

	if got == nil || got.ProcessID != 4242 || !bytes.Equal(got.SecretKey, serverKey.SecretKey) {
		t.Errorf("IssueKey got %+v; want the server's key", got)
	}
	want := concat(
		encode(t, &pgproto3.AuthenticationOk{}),
		encode(t, proxyKey),
		encode(t, &pgproto3.ReadyForQuery{TxStatus: 'I'}),
	)
	if !bytes.Equal(client.Bytes(), want) {
		t.Errorf("client got %q; want %q", client.Bytes(), want)
	}
}

func TestRelayStartupForwardsOtherMessagesUnchanged(t *testing.T) {
	want := concat(
		encode(t, &pgproto3.NegotiateProtocolVersion{NewestMinorProtocol: 0, UnrecognizedOptions: []string{"_pq_.x"}}),
		encode(t, &pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}}),
		encode(t, &pgproto3.AuthenticationSASLContinue{Data: []byte("r=abc,s=salt,i=4096")}),
		encode(t, &pgproto3.AuthenticationSASLFinal{Data: []byte("v=proof")}),
		encode(t, &pgproto3.AuthenticationOk{}),
		encode(t, &pgproto3.ParameterStatus{Name: "server_version", Value: "18.0"}),
		encode(t, &pgproto3.BackendKeyData{ProcessID: 4242, SecretKey: []byte{1, 2, 3, 4}}),
		encode(t, &pgproto3.ReadyForQuery{TxStatus: 'I'}),
	)
	var client bytes.Buffer

	if err := RelayStartup(&client, bytes.NewReader(want), StartupOptions{}); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(client.Bytes(), want) {
		t.Fatalf("client got %q; want %q", client.Bytes(), want)
	}
}

func TestRelayStartupStopsAtEndOfStartup(t *testing.T) {
	for name, end := range map[string]encoder{
		"ready": &pgproto3.ReadyForQuery{TxStatus: 'I'},
		"error": &pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "password authentication failed"},
	} {
		t.Run(name, func(t *testing.T) {
			server := bytes.NewReader(concat(encode(t, &pgproto3.AuthenticationOk{}), encode(t, end), []byte("after")))

			if err := RelayStartup(io.Discard, server, StartupOptions{}); err != nil {
				t.Fatal(err)
			}

			if rest, _ := io.ReadAll(server); string(rest) != "after" {
				t.Errorf("left %q unread; want %q", rest, "after")
			}
		})
	}
}

func TestRelayStartupRejects(t *testing.T) {
	issue := func(k *pgproto3.BackendKeyData) *pgproto3.BackendKeyData { return k }
	for name, in := range map[string][]byte{
		"length below 4":         concat([]byte("R"), u32(3)),
		"auth message too short": concat([]byte("R"), u32(6), []byte{0, 0}),
		"SASL list too long":     concat([]byte("R"), u32(4+4+maxPacketLen), u32(10)),
		"SASL list unterminated": concat([]byte("R"), u32(4+4+5), u32(10), []byte("SCRAM")),
		"key too short":          concat([]byte("K"), u32(4+7), u32(4242), []byte{1, 2, 3}),
		"key too long":           concat([]byte("K"), u32(4+4+257), u32(4242), make([]byte, 257)),
	} {
		t.Run(name, func(t *testing.T) {
			if err := RelayStartup(io.Discard, bytes.NewReader(in), StartupOptions{IssueKey: issue}); err == nil {
				t.Fatal("RelayStartup returned nil; want an error")
			}
		})
	}
}

func TestRelayStartupReportsEOFInsideMessage(t *testing.T) {
	ready := encode(t, &pgproto3.ReadyForQuery{TxStatus: 'I'})

	err := RelayStartup(io.Discard, bytes.NewReader(ready[:len(ready)-1]), StartupOptions{})

	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v; want io.ErrUnexpectedEOF", err)
	}
}

func FuzzRelayStartup(f *testing.F) {
	f.Add(concat(
		encodeF(f, &pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"}}),
		encodeF(f, &pgproto3.AuthenticationOk{}),
		encodeF(f, &pgproto3.BackendKeyData{ProcessID: 4242, SecretKey: bytes.Repeat([]byte{7}, 32)}),
		encodeF(f, &pgproto3.ReadyForQuery{TxStatus: 'I'}),
	))
	f.Fuzz(func(t *testing.T, in []byte) {
		issue := func(k *pgproto3.BackendKeyData) *pgproto3.BackendKeyData {
			if n := len(k.SecretKey); n < 4 || n > 256 {
				t.Fatalf("IssueKey got a %d-byte key; want 4 to 256", n)
			}
			return k
		}
		RelayStartup(io.Discard, bytes.NewReader(in), StartupOptions{IssueKey: issue})
	})
}
