package wire

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
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

func TestRelayStartupReportsParameters(t *testing.T) {
	want := concat(
		encode(t, &pgproto3.AuthenticationOk{}),
		encode(t, &pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"}),
		encode(t, &pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"}),
		encode(t, &pgproto3.ReadyForQuery{TxStatus: 'I'}),
	)
	var client bytes.Buffer
	var got []string

	err := RelayStartup(&client, bytes.NewReader(want), StartupOptions{Report: func(name, value string) {
		got = append(got, name+"="+value)
	}})
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(got, []string{"client_encoding=UTF8", "standard_conforming_strings=on"}) {
		t.Errorf("reported %q", got)
	}
	if !bytes.Equal(client.Bytes(), want) {
		t.Errorf("client got %q; want %q", client.Bytes(), want)
	}
}

func TestRelayStartupRefusesAfterAuthentication(t *testing.T) {
	for _, binding := range []bool{false, true} {
		ok := encode(t, &pgproto3.AuthenticationOk{})
		rest := concat(encode(t, &pgproto3.ParameterStatus{Name: "server_version", Value: "18.0"}), encode(t, &pgproto3.ReadyForQuery{TxStatus: 'I'}))
		server := bytes.NewReader(concat(encode(t, &pgproto3.AuthenticationSASLFinal{Data: []byte("v=proof")}), ok, rest))
		var client bytes.Buffer
		over := &Error{Code: "53300", Message: "queryguard: too many connections"}
		calls := 0

		err := RelayStartup(&client, server, StartupOptions{ChannelBinding: binding, Authenticated: func() *Error {
			calls++
			return over
		}})

		// Postgres too sends AuthenticationOk before refusing a role over its connection limit.
		if e, isErr := errors.AsType[*Error](err); !isErr || *e != *over {
			t.Errorf("binding %v: got %v; want %v", binding, err, over)
		}
		fatal := encode(t, &pgproto3.ErrorResponse{Severity: "FATAL", SeverityUnlocalized: "FATAL", Code: over.Code, Message: over.Message})
		if !bytes.HasSuffix(client.Bytes(), concat(ok, fatal)) {
			t.Errorf("binding %v: client got %q; want AuthenticationOk then the FATAL error", binding, client.Bytes())
		}
		if left, _ := io.ReadAll(server); calls != 1 || !bytes.Equal(left, rest) {
			t.Errorf("binding %v: %d calls, left %q unread; want 1 call and the rest unread", binding, calls, left)
		}
	}
}

func TestRelayStartupStopsAtEndOfStartup(t *testing.T) {
	for name, tc := range map[string]struct {
		end  encoder
		want error
	}{
		"ready": {&pgproto3.ReadyForQuery{TxStatus: 'I'}, nil},
		// Postgres sends an error during startup only to refuse the login, as for a wrong password.
		"error": {&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "password authentication failed"}, ErrLoginRefused},
	} {
		t.Run(name, func(t *testing.T) {
			server := bytes.NewReader(concat(encode(t, &pgproto3.AuthenticationOk{}), encode(t, tc.end), []byte("after")))
			var client bytes.Buffer

			if err := RelayStartup(&client, server, StartupOptions{}); !errors.Is(err, tc.want) {
				t.Fatalf("got %v; want %v", err, tc.want)
			}

			if !bytes.HasSuffix(client.Bytes(), encode(t, tc.end)) {
				t.Errorf("client got %q; want it to end with the server's last message", client.Bytes())
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
		"parameter unterminated": concat([]byte("S"), u32(4+3), []byte("abc")),
		"parameter too long":     concat([]byte("S"), u32(4+maxPacketLen+1)),
	} {
		t.Run(name, func(t *testing.T) {
			opts := StartupOptions{IssueKey: issue, Report: func(string, string) {}}
			if err := RelayStartup(io.Discard, bytes.NewReader(in), opts); err == nil {
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
		encodeF(f, &pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"}),
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
		RelayStartup(io.Discard, bytes.NewReader(in), StartupOptions{IssueKey: issue, Report: func(string, string) {}})
	})
}

func TestRefusedLoginCarriesPostgresCode(t *testing.T) {
	refusal := &pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "password authentication failed"}
	server := bytes.NewReader(encode(t, refusal))
	var client bytes.Buffer

	err := RelayStartup(&client, server, StartupOptions{})

	if e, ok := errors.AsType[*LoginRefusedError](err); !ok || e.Code != "28P01" || !errors.Is(err, ErrLoginRefused) {
		t.Fatalf("got %v; want a LoginRefusedError with code 28P01 that is ErrLoginRefused", err)
	}
	if !bytes.Equal(client.Bytes(), encode(t, refusal)) {
		t.Errorf("client got %q; want the refusal as sent", client.Bytes())
	}
}

func TestRelayAuthRepliesStopsAtTheFirstOtherMessage(t *testing.T) {
	password, sasl := encode(t, &pgproto3.PasswordMessage{Password: "secret"}), encode(t, &pgproto3.SASLResponse{Data: []byte("proof")})
	query := encode(t, &pgproto3.Query{String: "show kills"})
	client := bufio.NewReader(bytes.NewReader(concat(password, sasl, query)))
	var server bytes.Buffer

	if err := RelayAuthReplies(client, &server); err != nil {
		t.Fatal(err)
	}

	if want := concat(password, sasl); !bytes.Equal(server.Bytes(), want) {
		t.Errorf("server got %q; want the password and SASL replies", server.Bytes())
	}
	if rest, _ := io.ReadAll(client); !bytes.Equal(rest, query) {
		t.Errorf("left %q unread; want the query", rest)
	}
}

func TestRelayStartupExplainsAChannelBindingRefusal(t *testing.T) {
	refusal := &pgproto3.ErrorResponse{Severity: "FATAL", SeverityUnlocalized: "FATAL", Code: "08P01", Message: "SCRAM channel binding negotiation error"}
	for _, binding := range []bool{false, true} {
		server := bytes.NewReader(concat(
			encode(t, &pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"}}),
			encode(t, refusal)))
		var client bytes.Buffer

		if err := RelayStartup(&client, server, StartupOptions{ChannelBinding: binding}); !errors.Is(err, ErrLoginRefused) {
			t.Fatalf("binding %v: got %v; want the login refused", binding, err)
		}

		frontend := pgproto3.NewFrontend(&client, io.Discard)
		frontend.Receive()
		msg, err := frontend.Receive()
		e, ok := msg.(*pgproto3.ErrorResponse)
		if err != nil || !ok {
			t.Fatalf("binding %v: client got %#v, %v; want the ErrorResponse", binding, msg, err)
		}
		if hinted := strings.Contains(e.Hint, "channel_binding=disable"); hinted == binding || e.Message != refusal.Message {
			t.Errorf("binding %v: client got %q with hint %q; want a hint only when the proxy hid -PLUS", binding, e.Message, e.Hint)
		}
	}
}
