package wire

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

func TestRelayAuthRemovesChannelBindingMechanisms(t *testing.T) {
	server := bytes.NewReader(concat(
		encode(t, &pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"}}),
		encode(t, &pgproto3.AuthenticationOk{}),
	))
	var client bytes.Buffer

	if err := RelayAuth(&client, server); err != nil {
		t.Fatal(err)
	}

	f := pgproto3.NewFrontend(&client, io.Discard)
	msg, err := f.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if sasl := mustBe[*pgproto3.AuthenticationSASL](t, msg); !slices.Equal(sasl.AuthMechanisms, []string{"SCRAM-SHA-256"}) {
		t.Errorf("client was offered %q; want only SCRAM-SHA-256", sasl.AuthMechanisms)
	}
}

func TestRelayAuthForwardsOtherMessagesUnchanged(t *testing.T) {
	want := concat(
		encode(t, &pgproto3.NegotiateProtocolVersion{NewestMinorProtocol: 0, UnrecognizedOptions: []string{"_pq_.x"}}),
		encode(t, &pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}}),
		encode(t, &pgproto3.AuthenticationSASLContinue{Data: []byte("r=abc,s=salt,i=4096")}),
		encode(t, &pgproto3.AuthenticationSASLFinal{Data: []byte("v=proof")}),
		encode(t, &pgproto3.AuthenticationOk{}),
	)
	var client bytes.Buffer

	if err := RelayAuth(&client, bytes.NewReader(want)); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(client.Bytes(), want) {
		t.Fatalf("client got %q; want %q", client.Bytes(), want)
	}
}

func TestRelayAuthStopsAfterAuthentication(t *testing.T) {
	for name, end := range map[string]encoder{
		"ok":    &pgproto3.AuthenticationOk{},
		"error": &pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "password authentication failed"},
	} {
		t.Run(name, func(t *testing.T) {
			server := bytes.NewReader(concat(encode(t, end), []byte("after")))

			if err := RelayAuth(io.Discard, server); err != nil {
				t.Fatal(err)
			}

			if rest, _ := io.ReadAll(server); string(rest) != "after" {
				t.Errorf("left %q unread; want %q", rest, "after")
			}
		})
	}
}

func TestRelayAuthRejects(t *testing.T) {
	for name, in := range map[string][]byte{
		"length below 4":         concat([]byte("R"), u32(3)),
		"auth message too short": concat([]byte("R"), u32(6), []byte{0, 0}),
		"SASL list too long":     concat([]byte("R"), u32(4+4+maxPacketLen), u32(10)),
		"SASL list unterminated": concat([]byte("R"), u32(4+4+5), u32(10), []byte("SCRAM")),
	} {
		t.Run(name, func(t *testing.T) {
			if err := RelayAuth(io.Discard, bytes.NewReader(in)); err == nil {
				t.Fatal("RelayAuth returned nil; want an error")
			}
		})
	}
}

func TestRelayAuthReportsEOFInsideMessage(t *testing.T) {
	ok := encode(t, &pgproto3.AuthenticationOk{})

	err := RelayAuth(io.Discard, bytes.NewReader(ok[:len(ok)-1]))

	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v; want io.ErrUnexpectedEOF", err)
	}
}
