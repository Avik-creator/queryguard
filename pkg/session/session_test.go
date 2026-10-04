package session

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

func TestForwardsAllowedQuery(t *testing.T) {
	h := start(t, fakeChecker{})

	h.send(&pgproto3.Query{String: "select 1"})

	h.serverGets(&pgproto3.Query{String: "select 1"})
	h.reply(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
}

func TestAnswersRejectedQueryItself(t *testing.T) {
	h := start(t, fakeChecker{})

	h.send(&pgproto3.Query{String: "bad"})

	h.clientGets(rejected, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.serverGetsNothingBefore(&pgproto3.Query{String: "select 'next'"})
}

func TestRejectsQueryInTransactionThroughPostgres(t *testing.T) {
	h := start(t, fakeChecker{})
	h.begin()

	h.send(&pgproto3.Query{String: "bad"})

	h.serverGets(&pgproto3.Query{String: wantDo})
	h.reply(postgresError, &pgproto3.ReadyForQuery{TxStatus: 'E'})
	h.clientGets(postgresError, &pgproto3.ReadyForQuery{TxStatus: 'E'})
}

func TestAnswersRejectedParseItself(t *testing.T) {
	h := start(t, fakeChecker{})

	h.send(&pgproto3.Parse{Name: "s1", Query: "bad"}, &pgproto3.Bind{PreparedStatement: "s1"},
		&pgproto3.Describe{ObjectType: 'P'}, &pgproto3.Execute{}, &pgproto3.Sync{})

	h.clientGets(rejected, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.serverGetsNothingBefore(&pgproto3.Query{String: "select 'next'"})
}

func TestRejectsParseInTransactionThroughPostgres(t *testing.T) {
	h := start(t, fakeChecker{})
	h.begin()

	h.send(&pgproto3.Parse{Name: "s1", Query: "bad"}, &pgproto3.Bind{PreparedStatement: "s1"},
		&pgproto3.Describe{ObjectType: 'P'}, &pgproto3.Execute{}, &pgproto3.Sync{})

	h.serverGets(&pgproto3.Parse{Query: wantDo}, &pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Sync{})
	h.reply(&pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, postgresError, &pgproto3.ReadyForQuery{TxStatus: 'E'})
	h.clientGets(postgresError, &pgproto3.ReadyForQuery{TxStatus: 'E'})
}

func TestRejectedParseAfterOtherMessagesGoesThroughPostgres(t *testing.T) {
	h := start(t, fakeChecker{})

	// The first statement may already have run, so only Postgres can roll it back with the error.
	h.send(&pgproto3.Parse{Query: "select 1"}, &pgproto3.Bind{}, &pgproto3.Execute{},
		&pgproto3.Parse{Query: "bad"}, &pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Sync{})

	h.serverGets(&pgproto3.Parse{Query: "select 1"}, &pgproto3.Bind{}, &pgproto3.Execute{},
		&pgproto3.Parse{Query: wantDo}, &pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Sync{})
	h.reply(&pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, &pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
		&pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, postgresError, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(&pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, &pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
		postgresError, &pgproto3.ReadyForQuery{TxStatus: 'I'})
}

func TestRejectedParseBeforeSyncGoesThroughPostgres(t *testing.T) {
	h := start(t, fakeChecker{})
	h.send(&pgproto3.Parse{Query: "insert into notes values (1)"}, &pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Flush{})
	h.serverGets(&pgproto3.Parse{Query: "insert into notes values (1)"}, &pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Flush{})
	h.reply(&pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, &pgproto3.CommandComplete{CommandTag: []byte("INSERT 0 1")})
	h.clientGets(&pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, &pgproto3.CommandComplete{CommandTag: []byte("INSERT 0 1")})

	// Every answer is in, but the insert's implicit transaction stays open until Sync; only an error in Postgres rolls it back.
	h.send(&pgproto3.Parse{Query: "bad"}, &pgproto3.Sync{})

	h.serverGets(&pgproto3.Parse{Query: wantDo}, &pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Sync{})
}

func TestForgetsMessagesPostgresSkipsAfterAnError(t *testing.T) {
	h := start(t, fakeChecker{})
	h.send(&pgproto3.Parse{Query: "select oops"}, &pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Sync{})
	h.serverGets(&pgproto3.Parse{Query: "select oops"}, &pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Sync{})
	h.reply(postgresError, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(postgresError, &pgproto3.ReadyForQuery{TxStatus: 'I'})

	// Nothing is outstanding now, so the proxy can answer by itself again.
	h.send(&pgproto3.Query{String: "bad"})

	h.clientGets(rejected, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.serverGetsNothingBefore(&pgproto3.Query{String: "select 'next'"})
}

func TestForgetsMessagesSentWhilePostgresSkips(t *testing.T) {
	h := start(t, fakeChecker{})
	h.send(&pgproto3.Parse{Query: "select oops"}, &pgproto3.Flush{})
	h.serverGets(&pgproto3.Parse{Query: "select oops"}, &pgproto3.Flush{})
	h.reply(postgresError)
	h.clientGets(postgresError)

	h.send(&pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Sync{})
	h.serverGets(&pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Sync{})
	h.reply(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(&pgproto3.ReadyForQuery{TxStatus: 'I'})

	h.send(&pgproto3.Query{String: "bad"})

	h.clientGets(rejected, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.serverGetsNothingBefore(&pgproto3.Query{String: "select 'next'"})
}

func TestForwardsCopyData(t *testing.T) {
	h := start(t, fakeChecker{})

	h.send(&pgproto3.Query{String: "copy notes from stdin"})
	h.serverGets(&pgproto3.Query{String: "copy notes from stdin"})
	h.reply(&pgproto3.CopyInResponse{})
	h.clientGets(&pgproto3.CopyInResponse{})
	h.send(&pgproto3.CopyData{Data: []byte("1\n")}, &pgproto3.CopyDone{})

	h.serverGets(&pgproto3.CopyData{Data: []byte("1\n")}, &pgproto3.CopyDone{})
}

func TestStatementTooLongToCheck(t *testing.T) {
	long := "select '" + strings.Repeat("x", maxCheckedLen) + "'"
	for _, allow := range []bool{true, false} {
		h := start(t, fakeChecker{allowTooLong: allow})
		buf, _ := (&pgproto3.Query{String: long}).Encode(nil)

		// The proxy streams the message on while the test is still writing it, so the write can't block the reads below.
		go h.client.Write(buf)

		if allow {
			h.serverGets(&pgproto3.Query{String: long})
		} else {
			h.clientGets(rejected, &pgproto3.ReadyForQuery{TxStatus: 'I'})
			h.serverGetsNothingBefore(&pgproto3.Query{String: "select 'next'"})
		}
	}
}

func TestPassesEverythingWithoutChecker(t *testing.T) {
	h := start(t, nil)

	h.send(&pgproto3.Query{String: "bad"})

	h.serverGets(&pgproto3.Query{String: "bad"})
}

func TestEndsWhenClientLeaves(t *testing.T) {
	h := start(t, fakeChecker{})

	h.client.Close()

	h.pg.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := h.pg.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("server side read %v; want EOF once the client left", err)
	}
	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		t.Fatal("Relay did not return")
	}
}

// rejected is what fakeChecker returns for any statement containing "bad".
var rejected = &pgproto3.ErrorResponse{Severity: "ERROR", Code: "42501", Message: "queryguard: no", Hint: "it's bad"}

// wantDo raises rejected inside Postgres; the hint's quote is doubled once per level of quoting.
const wantDo = `DO 'BEGIN RAISE EXCEPTION USING ERRCODE = ''42501'', MESSAGE = ''queryguard: no'', HINT = ''it''''s bad''; END'`

// postgresError stands for whatever error Postgres sends.
var postgresError = &pgproto3.ErrorResponse{Severity: "ERROR", Code: "42601", Message: "syntax error"}

type fakeChecker struct{ allowTooLong bool }

func (fakeChecker) Check(sql string) *pgproto3.ErrorResponse {
	if strings.Contains(sql, "bad") {
		return rejected
	}
	return nil
}

func (c fakeChecker) CheckTooLong(int) *pgproto3.ErrorResponse {
	if c.allowTooLong {
		return nil
	}
	return rejected
}

// harness runs Relay between a test client and a test Postgres.
type harness struct {
	t      *testing.T
	client net.Conn      // the test's end, acting as the client
	pg     net.Conn      // the test's end, acting as Postgres
	done   chan struct{} // closed when Relay returns
}

func start(t *testing.T, check Checker) *harness {
	t.Helper()
	client, proxyClient := tcpPair(t)
	pg, proxyServer := tcpPair(t)
	h := &harness{t: t, client: client, pg: pg, done: make(chan struct{})}
	go func() {
		defer close(h.done)
		Relay(proxyClient, proxyServer, check, func(io.Writer, io.Reader) error { return nil })
	}()
	t.Cleanup(func() {
		client.Close()
		pg.Close()
		<-h.done
	})
	return h
}

// begin runs BEGIN so the session is in a transaction.
func (h *harness) begin() {
	h.t.Helper()
	h.send(&pgproto3.Query{String: "begin"})
	h.serverGets(&pgproto3.Query{String: "begin"})
	h.reply(&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")}, &pgproto3.ReadyForQuery{TxStatus: 'T'})
	h.clientGets(&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")}, &pgproto3.ReadyForQuery{TxStatus: 'T'})
}

func (h *harness) send(msgs ...encoder) { h.t.Helper(); write(h.t, h.client, msgs) }

func (h *harness) reply(msgs ...encoder) { h.t.Helper(); write(h.t, h.pg, msgs) }

// serverGets reads len(want) messages on the Postgres side and compares their encodings.
func (h *harness) serverGets(want ...encoder) {
	h.t.Helper()
	backend := pgproto3.NewBackend(h.pg, h.pg)
	for _, w := range want {
		h.pg.SetReadDeadline(time.Now().Add(2 * time.Second))
		got, err := backend.Receive()
		if err != nil {
			h.t.Fatalf("Postgres side: %v; want %#v", err, w)
		}
		expectSame(h.t, "Postgres", got, w)
	}
}

// serverGetsNothingBefore sends next and checks it is the first thing Postgres receives.
func (h *harness) serverGetsNothingBefore(next *pgproto3.Query) {
	h.t.Helper()
	h.send(next)
	h.serverGets(next)
}

// clientGets reads len(want) messages on the client side and compares their encodings.
func (h *harness) clientGets(want ...encoder) {
	h.t.Helper()
	frontend := pgproto3.NewFrontend(h.client, h.client)
	for _, w := range want {
		h.client.SetReadDeadline(time.Now().Add(2 * time.Second))
		got, err := frontend.Receive()
		if err != nil {
			h.t.Fatalf("client side: %v; want %#v", err, w)
		}
		expectSame(h.t, "client", got, w)
	}
}

type encoder interface{ Encode([]byte) ([]byte, error) }

func write(t *testing.T, conn net.Conn, msgs []encoder) {
	t.Helper()
	var buf []byte
	for _, m := range msgs {
		var err error
		if buf, err = m.Encode(buf); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.Write(buf); err != nil {
		t.Fatal(err)
	}
}

func expectSame(t *testing.T, side string, got, want encoder) {
	t.Helper()
	g, _ := got.Encode(nil)
	w, _ := want.Encode(nil)
	if string(g) != string(w) {
		t.Fatalf("%s got %#v; want %#v", side, got, want)
	}
}

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		a.Close()
		b.Close()
	})
	return a, b
}
