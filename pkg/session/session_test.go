package session

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Avik-creator/queryguard/internal/safe"
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

func TestTellsCheckerTheReportedSettings(t *testing.T) {
	seen := make(chan Settings, 4)
	h := start(t, fakeChecker{seen: seen})

	h.send(&pgproto3.Query{String: "set standard_conforming_strings = off"})
	h.serverGets(&pgproto3.Query{String: "set standard_conforming_strings = off"})
	expectSettings(t, seen, loginSettings)
	changed := &pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "off"}
	h.reply(&pgproto3.CommandComplete{CommandTag: []byte("SET")}, changed, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(&pgproto3.CommandComplete{CommandTag: []byte("SET")}, changed, &pgproto3.ReadyForQuery{TxStatus: 'I'})

	h.send(&pgproto3.Query{String: "select 1"})
	h.serverGets(&pgproto3.Query{String: "select 1"})
	expectSettings(t, seen, Settings{StandardConformingStrings: "off", ClientEncoding: "UTF8"})
}

func TestSettingsAreUnknownWhileStatementsAreInFlight(t *testing.T) {
	seen := make(chan Settings, 4)
	h := start(t, fakeChecker{seen: seen})

	// The first query may change a setting, and Postgres reads the second only after running it.
	h.send(&pgproto3.Query{String: "select 1"}, &pgproto3.Query{String: "select 2"})
	h.serverGets(&pgproto3.Query{String: "select 1"}, &pgproto3.Query{String: "select 2"})
	expectSettings(t, seen, loginSettings)
	expectSettings(t, seen, Settings{})
	h.reply(&pgproto3.ReadyForQuery{TxStatus: 'I'}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(&pgproto3.ReadyForQuery{TxStatus: 'I'}, &pgproto3.ReadyForQuery{TxStatus: 'I'})

	// Postgres reports changed settings just before ReadyForQuery, so they stay unknown until a Sync is answered.
	h.send(&pgproto3.Parse{Query: "select 3"}, &pgproto3.Flush{})
	h.serverGets(&pgproto3.Parse{Query: "select 3"}, &pgproto3.Flush{})
	expectSettings(t, seen, loginSettings)
	h.reply(&pgproto3.ParseComplete{})
	h.clientGets(&pgproto3.ParseComplete{})
	h.send(&pgproto3.Parse{Query: "select 4"}, &pgproto3.Sync{})
	h.serverGets(&pgproto3.Parse{Query: "select 4"}, &pgproto3.Sync{})
	expectSettings(t, seen, Settings{})
}

func expectSettings(t *testing.T, seen <-chan Settings, want Settings) {
	t.Helper()
	select {
	case got := <-seen:
		if got != want {
			t.Fatalf("checker was told %+v; want %+v", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("checker was not called")
	}
}

func TestExplainsQueryBeforeRunningIt(t *testing.T) {
	h := start(t, fakeChecker{})

	h.send(&pgproto3.Query{String: "select plan"})

	h.serverGets(&pgproto3.Query{String: explainPrefix + "select plan"})
	h.reply(&pgproto3.RowDescription{}, plan("small"), &pgproto3.CommandComplete{CommandTag: []byte("EXPLAIN")}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.serverGets(&pgproto3.Query{String: "select plan"})
	h.reply(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
}

func TestRejectsQueryByItsPlan(t *testing.T) {
	h := start(t, fakeChecker{})

	h.send(&pgproto3.Query{String: "select plan"})
	h.serverGets(&pgproto3.Query{String: explainPrefix + "select plan"})
	h.reply(plan("big"), &pgproto3.CommandComplete{CommandTag: []byte("EXPLAIN")}, &pgproto3.ReadyForQuery{TxStatus: 'I'})

	h.clientGets(tooCostly, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.serverGetsNothingBefore(&pgproto3.Query{String: "select 'next'"})
}

func TestPassesOnPostgresErrorFromExplainingQuery(t *testing.T) {
	h := start(t, fakeChecker{})

	h.send(&pgproto3.Query{String: "select plan from nowhere"})
	h.serverGets(&pgproto3.Query{String: explainPrefix + "select plan from nowhere"})
	h.reply(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42P01", Message: "relation \"nowhere\" does not exist", Position: int32(len(explainPrefix)) + 18},
		&pgproto3.ReadyForQuery{TxStatus: 'I'})

	// The query itself would fail the same way, so the client gets the error at the place in its own text.
	h.clientGets(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42P01", Message: "relation \"nowhere\" does not exist", Position: 18},
		&pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.serverGetsNothingBefore(&pgproto3.Query{String: "select 'next'"})
}

func TestExplainsBindWithItsValues(t *testing.T) {
	h := start(t, fakeChecker{})
	parse := &pgproto3.Parse{Name: "s1", Query: "select plan where id = $1", ParameterOIDs: []uint32{23}}
	bind := &pgproto3.Bind{PreparedStatement: "s1", ParameterFormatCodes: []int16{1}, Parameters: [][]byte{{0, 0, 0, 7}}, ResultFormatCodes: []int16{1}}

	h.send(parse, bind, &pgproto3.Execute{}, &pgproto3.Sync{})

	h.serverGets(append([]encoder{parse}, explainBind(explainPrefix+parse.Query, []uint32{23}, []int16{1}, [][]byte{{0, 0, 0, 7}})...)...)
	h.reply(&pgproto3.ParseComplete{}, &pgproto3.CloseComplete{}, &pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, plan("small"),
		&pgproto3.CommandComplete{CommandTag: []byte("EXPLAIN")}, &pgproto3.CloseComplete{})
	h.serverGets(bind, &pgproto3.Execute{}, &pgproto3.Sync{})
	h.clientGets(&pgproto3.ParseComplete{})
}

func TestExplainLeavesAClientStatementOfAnyNameAlone(t *testing.T) {
	h := start(t, fakeChecker{})
	// The name the proxy once used for its own EXPLAIN statement.
	parse := &pgproto3.Parse{Name: "queryguard_explain", Query: "select plan"}

	h.send(parse, &pgproto3.Bind{PreparedStatement: parse.Name}, &pgproto3.Execute{}, &pgproto3.Sync{})

	// The client's Parse, then the proxy's EXPLAIN messages.
	backend := pgproto3.NewBackend(h.pg, h.pg)
	for range 1 + len(explainBind("", nil, nil, nil)) {
		h.pg.SetReadDeadline(time.Now().Add(2 * time.Second))
		msg, err := backend.Receive()
		if err != nil {
			t.Fatal(err)
		}
		if c, ok := msg.(*pgproto3.Close); ok && c.Name == parse.Name {
			t.Fatalf("proxy closed the client's statement %q for its EXPLAIN", c.Name)
		}
	}
}

func TestTellsCheckerWhichValuesWereBound(t *testing.T) {
	values := make(chan string, 10)
	h := start(t, fakeChecker{values: values})
	parse := &pgproto3.Parse{Name: "s1", Query: "select plan where id = $1"}
	h.send(parse)
	h.serverGets(parse)
	h.reply(&pgproto3.ParseComplete{})
	h.clientGets(&pgproto3.ParseComplete{})

	var got []string
	for _, v := range []string{"7", "8", "7"} {
		bind := &pgproto3.Bind{PreparedStatement: "s1", Parameters: [][]byte{[]byte(v)}}
		h.send(bind, &pgproto3.Execute{}, &pgproto3.Sync{})
		h.serverGets(explainBind(explainPrefix+parse.Query, nil, nil, [][]byte{[]byte(v)})...)
		h.reply(&pgproto3.CloseComplete{}, &pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, plan("small"),
			&pgproto3.CommandComplete{CommandTag: []byte("EXPLAIN")}, &pgproto3.CloseComplete{})
		h.serverGets(bind, &pgproto3.Execute{}, &pgproto3.Sync{})
		h.reply(&pgproto3.BindComplete{}, &pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
		h.clientGets(&pgproto3.BindComplete{}, &pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
		got = append(got, <-values)
	}

	// The checker keys plans by the values, so the same values must give the same digest and other values another.
	if got[0] == "" || got[0] == got[1] || got[0] != got[2] {
		t.Errorf("values digests %q; want the first and last equal, the middle different, none empty", got)
	}
}

func TestRejectsBindByItsPlanThroughPostgres(t *testing.T) {
	h := start(t, fakeChecker{})
	parse := &pgproto3.Parse{Name: "s1", Query: "select plan"}

	h.send(parse, &pgproto3.Bind{PreparedStatement: "s1"}, &pgproto3.Execute{}, &pgproto3.Sync{})

	h.serverGets(append([]encoder{parse}, explainBind(explainPrefix+"select plan", nil, nil, nil)...)...)
	h.reply(&pgproto3.ParseComplete{}, &pgproto3.CloseComplete{}, &pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, plan("big"),
		&pgproto3.CommandComplete{CommandTag: []byte("EXPLAIN")}, &pgproto3.CloseComplete{})
	// The EXPLAIN opened the batch's implicit transaction, so Postgres must end it with the error.
	h.serverGets(&pgproto3.Parse{Query: wantCostDo}, &pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Sync{})
	h.reply(&pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, postgresError, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(&pgproto3.ParseComplete{}, postgresError, &pgproto3.ReadyForQuery{TxStatus: 'I'})
}

func TestPassesOnPostgresErrorFromExplainingBind(t *testing.T) {
	h := start(t, fakeChecker{})
	parse := &pgproto3.Parse{Name: "s1", Query: "select plan where id = $1"}
	bind := &pgproto3.Bind{PreparedStatement: "s1", Parameters: [][]byte{[]byte("x")}}

	h.send(parse, bind, &pgproto3.Execute{}, &pgproto3.Sync{})

	h.serverGets(append([]encoder{parse}, explainBind(explainPrefix+parse.Query, nil, nil, [][]byte{[]byte("x")})...)...)
	h.reply(&pgproto3.ParseComplete{}, &pgproto3.CloseComplete{}, &pgproto3.ParseComplete{}, postgresError)
	// Postgres now skips to Sync, as it would after the client's own Bind failed.
	h.serverGets(&pgproto3.Sync{})
	h.reply(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(&pgproto3.ParseComplete{}, postgresError, &pgproto3.ReadyForQuery{TxStatus: 'I'})
}

func TestExplainsGenericPlanForLargeValues(t *testing.T) {
	explained := make(chan bool, 1)
	h := start(t, fakeChecker{generic: explained})
	parse := &pgproto3.Parse{Name: "s1", Query: "select plan where data = $1"}
	bind := &pgproto3.Bind{PreparedStatement: "s1", Parameters: [][]byte{make([]byte, maxReplayed)}}

	h.send(parse)
	h.serverGets(parse)
	// The proxy streams the Bind on while the test is still writing it.
	buf, _ := bind.Encode(nil)
	go h.client.Write(buf)

	// GENERIC_PLAN ignores the values, but Postgres still wants one per parameter, so they are sent as NULLs.
	h.serverGets(explainBind(genericPrefix+parse.Query, nil, nil, [][]byte{nil})...)
	h.reply(&pgproto3.ParseComplete{}, &pgproto3.CloseComplete{}, &pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, plan("small"),
		&pgproto3.CommandComplete{CommandTag: []byte("EXPLAIN")}, &pgproto3.CloseComplete{})
	h.serverGets(bind)
	if !<-explained {
		t.Error("the cost check was not told the plan is generic")
	}
}

func TestExplainsBindOnlyUnderTheSettingsItWasParsedWith(t *testing.T) {
	h := start(t, fakeChecker{})
	parse := &pgproto3.Parse{Name: "s1", Query: `select plan where note = 'a\b'`}
	h.send(parse, &pgproto3.Sync{})
	h.serverGets(parse, &pgproto3.Sync{})
	h.reply(&pgproto3.ParseComplete{}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(&pgproto3.ParseComplete{}, &pgproto3.ReadyForQuery{TxStatus: 'I'})

	h.send(&pgproto3.Bind{PreparedStatement: "s1"}, &pgproto3.Sync{})
	h.serverGets(explainBind(explainPrefix+parse.Query, nil, nil, nil)...)
	h.reply(&pgproto3.CloseComplete{}, &pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, plan("small"),
		&pgproto3.CommandComplete{CommandTag: []byte("EXPLAIN")}, &pgproto3.CloseComplete{})
	h.serverGets(&pgproto3.Bind{PreparedStatement: "s1"}, &pgproto3.Sync{})
	h.reply(&pgproto3.BindComplete{}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(&pgproto3.BindComplete{}, &pgproto3.ReadyForQuery{TxStatus: 'I'})

	changed := &pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "off"}
	h.send(&pgproto3.Query{String: "set standard_conforming_strings = off"})
	h.serverGets(&pgproto3.Query{String: "set standard_conforming_strings = off"})
	h.reply(&pgproto3.CommandComplete{CommandTag: []byte("SET")}, changed, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(&pgproto3.CommandComplete{CommandTag: []byte("SET")}, changed, &pgproto3.ReadyForQuery{TxStatus: 'I'})

	// Postgres read the text when it was parsed; read again now, its backslash would be an escape.
	h.send(&pgproto3.Bind{PreparedStatement: "s1"})
	h.serverGets(&pgproto3.Bind{PreparedStatement: "s1"})
}

func TestForgetsClosedStatements(t *testing.T) {
	h := start(t, fakeChecker{})
	parse := &pgproto3.Parse{Name: "s1", Query: "select plan"}
	h.send(parse, &pgproto3.Close{ObjectType: 'S', Name: "s1"}, &pgproto3.Sync{})
	h.serverGets(parse, &pgproto3.Close{ObjectType: 'S', Name: "s1"}, &pgproto3.Sync{})
	h.reply(&pgproto3.ParseComplete{}, &pgproto3.CloseComplete{}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(&pgproto3.ParseComplete{}, &pgproto3.CloseComplete{}, &pgproto3.ReadyForQuery{TxStatus: 'I'})

	h.send(&pgproto3.Bind{PreparedStatement: "s1"})

	h.serverGets(&pgproto3.Bind{PreparedStatement: "s1"})
}

func TestEndsWhilePostgresExplains(t *testing.T) {
	h := start(t, fakeChecker{})
	h.send(&pgproto3.Query{String: "select plan"})
	h.serverGets(&pgproto3.Query{String: explainPrefix + "select plan"})

	h.pg.Close()

	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		t.Fatal("Relay still waits for the plan after Postgres went away")
	}
}

func TestHoldsSlotUntilPostgresIsIdle(t *testing.T) {
	a := newAdmitter()
	h := start(t, fakeChecker{admit: a})

	h.send(&pgproto3.Query{String: "select slot"})
	h.serverGets(&pgproto3.Query{String: "select slot"})
	expect(t, a.running, false)
	h.reply(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
	expectNone(t, a.released, "slot freed before ReadyForQuery")

	h.reply(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	expect(t, a.released, struct{}{})
}

func TestPipelineTakesOneSlot(t *testing.T) {
	a := newAdmitter()
	h := start(t, fakeChecker{admit: a})
	p1, p2 := &pgproto3.Parse{Name: "a", Query: "select slot 1"}, &pgproto3.Parse{Name: "b", Query: "select slot 2"}

	h.send(p1, p2, &pgproto3.Bind{PreparedStatement: "a"}, &pgproto3.Execute{}, &pgproto3.Bind{PreparedStatement: "b"}, &pgproto3.Execute{}, &pgproto3.Sync{})

	h.serverGets(p1, p2, &pgproto3.Bind{PreparedStatement: "a"}, &pgproto3.Execute{}, &pgproto3.Bind{PreparedStatement: "b"}, &pgproto3.Execute{}, &pgproto3.Sync{})
	expect(t, a.running, false)
	expect(t, a.running, true)
	h.reply(&pgproto3.ParseComplete{}, &pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, &pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
		&pgproto3.BindComplete{}, &pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	expect(t, a.released, struct{}{})
	expectNone(t, a.released, "a second slot was freed")
}

func TestCancelsStatementPastItsTimeout(t *testing.T) {
	a := newAdmitter()
	a.timeout = 50 * time.Millisecond
	h := start(t, fakeChecker{admit: a})

	h.send(&pgproto3.Query{String: "select slot, pg_sleep(60)"})
	h.serverGets(&pgproto3.Query{String: "select slot, pg_sleep(60)"})

	expect(t, h.cancels, struct{}{})
	h.reply(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "57014", Message: "canceling statement due to user request"},
		&pgproto3.ReadyForQuery{TxStatus: 'I'})
	// The cancel came from QueryGuard's timeout, not from the client, so the error says so.
	h.clientGets(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "57014", Message: "queryguard: canceling statement due to statement timeout"},
		&pgproto3.ReadyForQuery{TxStatus: 'I'})
}

func TestInterruptCancelsWithItsOwnError(t *testing.T) {
	h := start(t, fakeChecker{})
	h.send(&pgproto3.Query{String: "alter table orders add column note text"})
	h.serverGets(&pgproto3.Query{String: "alter table orders add column note text"})

	lockTimeout := Interruption{Code: "55P03", Message: "queryguard: canceling statement due to lock timeout", Hint: "Retry later."}
	if !h.interrupt(lockTimeout) {
		t.Fatal("interrupt of a running statement reported nothing to cancel")
	}

	expect(t, h.cancels, struct{}{})
	h.reply(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "57014", Message: "canceling statement due to user request"},
		&pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "55P03", Message: lockTimeout.Message, Hint: lockTimeout.Hint},
		&pgproto3.ReadyForQuery{TxStatus: 'I'})
}

func TestIdleIsCalledOnceTheServerIsIdleEvenIfTheStatementNeverRan(t *testing.T) {
	a := newAdmitter()
	h := start(t, fakeChecker{admit: a})

	// A Bind without an Execute passes the gate, but Postgres never runs the statement, so it never reports how it ran.
	h.send(&pgproto3.Parse{Name: "s1", Query: "select slot"}, &pgproto3.Bind{PreparedStatement: "s1"}, &pgproto3.Sync{})
	h.serverGets(&pgproto3.Parse{Name: "s1", Query: "select slot"}, &pgproto3.Bind{PreparedStatement: "s1"}, &pgproto3.Sync{})
	expect(t, a.running, false)
	expectNone(t, a.idled, "called Idle while the server was busy")
	h.reply(&pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, &pgproto3.ReadyForQuery{TxStatus: 'I'})

	expect(t, a.idled, struct{}{})
	expectNone(t, a.ran, "reported a run of a statement never executed")
}

func TestInterruptLeavesAnIdleSessionAlone(t *testing.T) {
	h := start(t, fakeChecker{})

	if h.interrupt(Interruption{Code: "55P03", Message: "queryguard: canceling statement due to lock timeout"}) {
		t.Error("interrupt of an idle session reported a cancel")
	}
	expectNone(t, h.cancels, "cancelled an idle session")
}

func TestNoCancelForStatementWithinItsTimeout(t *testing.T) {
	a := newAdmitter()
	a.timeout = 200 * time.Millisecond
	h := start(t, fakeChecker{admit: a})

	h.send(&pgproto3.Query{String: "select slot"})
	h.serverGets(&pgproto3.Query{String: "select slot"})
	h.reply(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(&pgproto3.ReadyForQuery{TxStatus: 'I'})

	time.Sleep(300 * time.Millisecond)
	expectNone(t, h.cancels, "cancelled an idle session")
}

func TestEndsSessionIdleInTransaction(t *testing.T) {
	a := newAdmitter()
	a.idle = 50 * time.Millisecond
	h := start(t, fakeChecker{admit: a})

	h.send(&pgproto3.Query{String: "begin slot"})
	h.serverGets(&pgproto3.Query{String: "begin slot"})
	h.reply(&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")}, &pgproto3.ReadyForQuery{TxStatus: 'T'})

	// Postgres ends such a session with the same error for idle_in_transaction_session_timeout.
	h.clientGets(&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")}, &pgproto3.ReadyForQuery{TxStatus: 'T'},
		&pgproto3.ErrorResponse{Severity: "FATAL", SeverityUnlocalized: "FATAL", Code: "25P03",
			Message: "queryguard: terminating connection due to idle-in-transaction timeout"})
	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		t.Fatal("Relay did not end the session")
	}
}

func TestKeepsSessionIdleOutsideTransaction(t *testing.T) {
	a := newAdmitter()
	a.idle = 50 * time.Millisecond
	h := start(t, fakeChecker{admit: a})

	h.send(&pgproto3.Query{String: "select slot"})
	h.serverGets(&pgproto3.Query{String: "select slot"})
	h.reply(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(&pgproto3.ReadyForQuery{TxStatus: 'I'})

	time.Sleep(150 * time.Millisecond)
	h.serverGetsNothingBefore(&pgproto3.Query{String: "select 'still here'"})
}

func TestCancelsWhenClientLeavesMidStatement(t *testing.T) {
	h := start(t, fakeChecker{})
	h.send(&pgproto3.Query{String: "select pg_sleep(60)"})
	h.serverGets(&pgproto3.Query{String: "select pg_sleep(60)"})

	h.client.Close()

	expect(t, h.cancels, struct{}{})
}

func TestNoCancelWhenIdleClientLeaves(t *testing.T) {
	h := start(t, fakeChecker{})
	h.send(&pgproto3.Query{String: "select 1"})
	h.serverGets(&pgproto3.Query{String: "select 1"})
	h.reply(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(&pgproto3.ReadyForQuery{TxStatus: 'I'})

	h.client.Close()
	<-h.done

	expectNone(t, h.cancels, "cancelled after an idle client left")
}

func TestDropsWaitingStatementWhenClientLeaves(t *testing.T) {
	a := newAdmitter()
	h := start(t, fakeChecker{admit: a})
	h.send(&pgproto3.Query{String: "select wait"})
	time.Sleep(100 * time.Millisecond)

	h.client.Close()

	if err := <-a.waited; !errors.Is(err, context.Canceled) {
		t.Errorf("the wait ended with %v; want it cancelled", err)
	}
	h.pg.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := h.pg.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("Postgres got %v; want the session closed with nothing sent", err)
	}
}

func TestBindPassesGateEvenWhenItCannotBeExplained(t *testing.T) {
	a := newAdmitter()
	h := start(t, fakeChecker{admit: a})
	parse := &pgproto3.Parse{Name: "s1", Query: `select slot where note = 'a\b'`}
	h.send(parse, &pgproto3.Bind{PreparedStatement: "s1"}, &pgproto3.Sync{})

	// The settings are unknown at Bind, with the Parse in flight, so there is no EXPLAIN, but the slot is taken.
	h.serverGets(parse, &pgproto3.Bind{PreparedStatement: "s1"}, &pgproto3.Sync{})
	expect(t, a.running, false)
}

func TestReportsHowLongQueryRan(t *testing.T) {
	a := newAdmitter()
	h := start(t, fakeChecker{admit: a})

	h.send(&pgproto3.Query{String: "select slot"})
	h.serverGets(&pgproto3.Query{String: "select slot"})
	time.Sleep(50 * time.Millisecond)
	h.reply(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}, &pgproto3.ReadyForQuery{TxStatus: 'I'})

	if r := <-a.ran; !r.finished || r.took < 50*time.Millisecond || r.took > time.Second {
		t.Errorf("ran %+v; want finished after about 50ms", r)
	}
}

func TestReportsFailedQuery(t *testing.T) {
	a := newAdmitter()
	h := start(t, fakeChecker{admit: a})

	h.send(&pgproto3.Query{String: "select slot"})
	h.serverGets(&pgproto3.Query{String: "select slot"})
	h.reply(postgresError, &pgproto3.ReadyForQuery{TxStatus: 'I'})

	if r := <-a.ran; r.finished {
		t.Errorf("ran %+v; want unfinished, since Postgres raised an error", r)
	}
}

func TestReportsNoTimeForStatementsOfAPipeline(t *testing.T) {
	a := newAdmitter()
	h := start(t, fakeChecker{admit: a})
	p1, p2 := &pgproto3.Parse{Name: "a", Query: "select slot 1"}, &pgproto3.Parse{Name: "b", Query: "select slot 2"}

	h.send(p1, p2, &pgproto3.Bind{PreparedStatement: "a"}, &pgproto3.Execute{}, &pgproto3.Bind{PreparedStatement: "b"}, &pgproto3.Execute{}, &pgproto3.Sync{})
	h.serverGets(p1, p2, &pgproto3.Bind{PreparedStatement: "a"}, &pgproto3.Execute{}, &pgproto3.Bind{PreparedStatement: "b"}, &pgproto3.Execute{}, &pgproto3.Sync{})
	time.Sleep(50 * time.Millisecond)
	// Postgres holds its answers until Sync, so the first statement's answer arrives only once the second has run.
	h.reply(&pgproto3.ParseComplete{}, &pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, &pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
		&pgproto3.BindComplete{}, postgresError, &pgproto3.ReadyForQuery{TxStatus: 'I'})

	first, second := <-a.ran, <-a.ran
	if !first.finished || first.took != 0 || second.finished || second.took != 0 {
		t.Errorf("ran %+v, then %+v; want finished, then failed, neither with a time of its own", first, second)
	}
}

func TestReportsStatementOfItsOwnPortal(t *testing.T) {
	a := newAdmitter()
	h := start(t, fakeChecker{admit: a})
	p1, p2 := &pgproto3.Parse{Name: "a", Query: "select slot"}, &pgproto3.Parse{Name: "b", Query: "select 1"}
	b1, b2 := &pgproto3.Bind{DestinationPortal: "p1", PreparedStatement: "a"}, &pgproto3.Bind{DestinationPortal: "p2", PreparedStatement: "b"}

	h.send(p1, p2, b1, b2, &pgproto3.Execute{Portal: "p2"}, &pgproto3.Execute{Portal: "p1"}, &pgproto3.Sync{})
	h.serverGets(p1, p2, b1, b2, &pgproto3.Execute{Portal: "p2"}, &pgproto3.Execute{Portal: "p1"}, &pgproto3.Sync{})
	h.reply(&pgproto3.ParseComplete{}, &pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, &pgproto3.BindComplete{},
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})

	// p2's statement wasn't admitted, so its answer says nothing of how p1's ran.
	expectNone(t, a.ran, "p2's run was reported for p1's statement")
	h.reply(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	expect(t, a.ran, run{finished: true})
}

func TestSettlesOnceOutsideTransaction(t *testing.T) {
	a := newAdmitter()
	h := start(t, fakeChecker{admit: a})
	h.send(&pgproto3.Query{String: "begin"})
	h.serverGets(&pgproto3.Query{String: "begin"})
	h.reply(&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")}, &pgproto3.ReadyForQuery{TxStatus: 'T'})

	h.send(&pgproto3.Query{String: "create index slot"})
	h.serverGets(&pgproto3.Query{String: "create index slot"})
	h.reply(&pgproto3.CommandComplete{CommandTag: []byte("CREATE INDEX")}, &pgproto3.ReadyForQuery{TxStatus: 'T'})
	expectNone(t, a.settled, "settled inside the transaction")

	h.send(&pgproto3.Query{String: "commit"})
	h.serverGets(&pgproto3.Query{String: "commit"})
	h.reply(&pgproto3.CommandComplete{CommandTag: []byte("COMMIT")}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	expect(t, a.settled, struct{}{})
}

// expect waits up to 2s for a value on ch and compares it with want.
func expect[T comparable](t *testing.T, ch <-chan T, want T) {
	t.Helper()
	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("got %v; want %v", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("nothing arrived; want %v", want)
	}
}

// expectNone fails the test if ch gets a value within 100ms.
func expectNone[T any](t *testing.T, ch <-chan T, what string) {
	t.Helper()
	select {
	case v := <-ch:
		t.Fatalf("%s: %v", what, v)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestPassesEverythingWithoutChecker(t *testing.T) {
	h := start(t, nil)

	h.send(&pgproto3.Query{String: "bad"})

	h.serverGets(&pgproto3.Query{String: "bad"})
}

func TestChecksNothingAfterRefusedLogin(t *testing.T) {
	seen := make(chan Settings, 10)
	refused, release := errors.New("password authentication failed"), make(chan struct{})
	h := startWithLogin(t, fakeChecker{seen: seen}, func(io.Writer, io.Reader, func(string, string)) error {
		<-release
		return refused
	})

	// A client can send a statement without waiting for its login's outcome; the delay lets the session read it first.
	h.send(&pgproto3.Query{String: "select 1"})
	time.Sleep(50 * time.Millisecond)
	close(release)

	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		t.Fatal("Relay did not return")
	}
	if !errors.Is(h.err, refused) {
		t.Errorf("Relay returned %v; want the login's error", h.err)
	}
	expectNone(t, seen, "statement checked for a client that never logged in")
}

func TestSendsThePasswordAQueryArrivedWith(t *testing.T) {
	answered := make(chan struct{})
	answer := sync.OnceFunc(func() { close(answered) })
	h := startWithLogin(t, fakeChecker{}, func(io.Writer, io.Reader, func(string, string)) error {
		<-answered
		return nil
	})
	// Registered after start's cleanup, so it runs first and lets Relay return.
	t.Cleanup(answer)
	password := &pgproto3.PasswordMessage{Password: "secret"}

	// One write: the query waits for the login, which waits on Postgres getting the password.
	h.send(password, &pgproto3.Query{String: "select 1"})

	want, _ := password.Encode(nil)
	got := make([]byte, len(want))
	h.pg.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(h.pg, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Postgres got %q, %v; want the password message", got, err)
	}
	answer()
	h.serverGets(&pgproto3.Query{String: "select 1"})
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

// tooCostly is what fakeChecker's cost check returns for a plan containing "big".
var tooCostly = &pgproto3.ErrorResponse{Severity: "ERROR", Code: "54000", Message: "queryguard: too costly"}

// wantCostDo raises tooCostly inside Postgres.
const wantCostDo = `DO 'BEGIN RAISE EXCEPTION USING ERRCODE = ''54000'', MESSAGE = ''queryguard: too costly''; END'`

// plan is a one-column row of EXPLAIN output.
func plan(text string) *pgproto3.DataRow { return &pgproto3.DataRow{Values: [][]byte{[]byte(text)}} }

// explainBind is what the proxy sends to explain a bound statement: its own statement and portal, closed before and after.
func explainBind(sql string, types []uint32, formats []int16, values [][]byte) []encoder {
	return []encoder{
		&pgproto3.Close{ObjectType: 'S', Name: explainName},
		&pgproto3.Parse{Name: explainName, Query: sql, ParameterOIDs: types},
		&pgproto3.Bind{DestinationPortal: explainName, PreparedStatement: explainName, ParameterFormatCodes: formats, Parameters: values},
		&pgproto3.Execute{Portal: explainName},
		&pgproto3.Close{ObjectType: 'S', Name: explainName},
		&pgproto3.Flush{},
	}
}

// postgresError stands for whatever error Postgres sends.
var postgresError = &pgproto3.ErrorResponse{Severity: "ERROR", Code: "42601", Message: "syntax error"}

// loginSettings are the settings the harness's login reports.
var loginSettings = Settings{StandardConformingStrings: "on", ClientEncoding: "UTF8"}

// fakeChecker rejects "bad", costs "plan" (rejecting "big" plans), admits "slot" as admit says, and holds "wait" until its wait ends.
type fakeChecker struct {
	allowTooLong bool
	seen         chan<- Settings // gets the settings of each checked statement, when set
	generic      chan<- bool     // gets whether each plan explained was generic, when set
	values       chan<- string   // gets the values digest of each plan explained, when set
	admit        *admitter       // admits "slot" statements, when set
}

// admitter admits statements with a slot and limits, recording each gate's running and each release.
type admitter struct {
	timeout, idle, tx time.Duration
	maxRows, maxBytes int64
	returned          chan [2]int64 // gets the rows and bytes each admitted statement returned
	broke             chan string   // gets the code of each limit an admitted statement broke
	running           chan bool     // gets running from each gate
	released          chan struct{} // gets a value when a slot is freed
	waited            chan error    // gets why each "wait" statement's wait ended
	ran               chan run      // gets how each admitted statement ran
	settled           chan struct{} // gets a value when an admitted statement's transaction has ended
	idled             chan struct{} // gets a value when the server is idle after an admitted statement
}

// run is what a session reports of a statement once it ends.
type run struct {
	took     time.Duration
	finished bool
}

func newAdmitter() *admitter {
	return &admitter{running: make(chan bool, 10), released: make(chan struct{}, 10), waited: make(chan error, 10), ran: make(chan run, 10),
		settled: make(chan struct{}, 10), idled: make(chan struct{}, 10), returned: make(chan [2]int64, 10),
		broke: make(chan string, 10)}
}

func (c fakeChecker) Check(sql string, set Settings) (*pgproto3.ErrorResponse, Gate) {
	if c.seen != nil {
		c.seen <- set
	}
	switch {
	case strings.Contains(sql, "bad"):
		return rejected, nil
	case strings.Contains(sql, "wait"):
		return nil, func(ctx context.Context, _ Explain, _ bool) Admission {
			<-ctx.Done()
			c.admit.waited <- ctx.Err()
			return Admission{Reject: tooCostly}
		}
	case strings.Contains(sql, "slot"):
		return nil, func(_ context.Context, _ Explain, running bool) Admission {
			c.admit.running <- running
			a := Admission{Timeout: c.admit.timeout, IdleInTransaction: c.admit.idle, TransactionTimeout: c.admit.tx,
				MaxRows: c.admit.maxRows, MaxBytes: c.admit.maxBytes, Returned: func(rows, bytes int64) { c.admit.returned <- [2]int64{rows, bytes} },
				Broke: func(i Interruption) { c.admit.broke <- i.Code },
				Ran: func(took time.Duration, finished bool) {
					c.admit.ran <- run{took, finished}
				}, Settled: func() { c.admit.settled <- struct{}{} }, Idle: func() { c.admit.idled <- struct{}{} }}
			if !running {
				a.Release = sync.OnceFunc(func() { c.admit.released <- struct{}{} })
			}
			return a
		}
	case !strings.Contains(sql, "plan"):
		return nil, nil
	}
	return nil, func(_ context.Context, e Explain, _ bool) Admission {
		if e.Run == nil {
			return Admission{}
		}
		out, _ := e.Run()
		if c.generic != nil {
			c.generic <- e.Generic
		}
		if c.values != nil {
			c.values <- e.Values
		}
		if strings.Contains(out, "big") {
			return Admission{Reject: tooCostly}
		}
		return Admission{}
	}
}

func (c fakeChecker) CheckTooLong(int) *pgproto3.ErrorResponse {
	if c.allowTooLong {
		return nil
	}
	return rejected
}

// harness runs Relay between a test client and a test Postgres.
type harness struct {
	t       *testing.T
	client  net.Conn      // the test's end, acting as the client
	pg      net.Conn      // the test's end, acting as Postgres
	done    chan struct{} // closed when Relay returns
	cancels chan struct{} // gets a value each time the session asks Postgres to cancel
	err     error         // what Relay returned, once done is closed

	interrupts chan func(Interruption) bool // gets Options.Interrupt's func
}

// interrupt cancels what the session runs, with i as the reason.
func (h *harness) interrupt(i Interruption) bool {
	h.t.Helper()
	var f func(Interruption) bool
	select {
	case f = <-h.interrupts:
	case <-time.After(2 * time.Second):
		h.t.Fatal("Relay gave no interrupt func")
	}
	h.interrupts <- f
	return f(i)
}

func start(t *testing.T, check Checker) *harness {
	t.Helper()
	return startWithLogin(t, check, func(_ io.Writer, _ io.Reader, report func(name, value string)) error {
		report("standard_conforming_strings", loginSettings.StandardConformingStrings)
		report("client_encoding", loginSettings.ClientEncoding)
		report("TimeZone", "UTC")
		return nil
	})
}

// startWithLogin is start with the given login in place of one that succeeds at once.
func startWithLogin(t *testing.T, check Checker, login func(io.Writer, io.Reader, func(name, value string)) error) *harness {
	t.Helper()
	return startWith(t, Options{Check: check, Login: login})
}

// startWith is start with opts; the harness fills in Interrupt, a Cancel it hears of before opts's runs, and a login that succeeds at once when opts has none.
func startWith(t *testing.T, opts Options) *harness {
	t.Helper()
	client, proxyClient := tcpPair(t)
	pg, proxyServer := tcpPair(t)
	h := &harness{t: t, client: client, pg: pg, done: make(chan struct{}), cancels: make(chan struct{}, 10), interrupts: make(chan func(Interruption) bool, 1)}
	if opts.Login == nil {
		opts.Login = func(io.Writer, io.Reader, func(string, string)) error { return nil }
	}
	cancel := opts.Cancel
	opts.Cancel = func() {
		h.cancels <- struct{}{}
		if cancel != nil {
			cancel()
		}
	}
	opts.Interrupt = func(f func(Interruption) bool) { h.interrupts <- f }
	go func() {
		defer close(h.done)
		h.err = Relay(proxyClient, proxyServer, opts)
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

func TestRefusesAMessageLongerThanPostgresTakes(t *testing.T) {
	// A length near 4 GB would wrap to a negative int on a 32-bit build.
	head := []byte{'Q', 0xff, 0xff, 0xff, 0xf0}

	if _, n, err := readHeader(bufio.NewReader(bytes.NewReader(head))); err == nil {
		t.Fatalf("readHeader read a body of %d bytes; want an error", n)
	}
}

func TestPanicInTheClientLoopEndsOnlyThatSession(t *testing.T) {
	client, _, done := relayWith(t, Options{Check: panicChecker{}})

	write(t, client, []encoder{&pgproto3.Query{String: "select 1"}})

	expectPanic(t, done)
}

func TestPanicInAStatementTimerEndsOnlyThatSession(t *testing.T) {
	a := newAdmitter()
	a.timeout = 50 * time.Millisecond
	client, _, done := relayWith(t, Options{Check: fakeChecker{admit: a}, Cancel: func() { panic("bug") }})

	write(t, client, []encoder{&pgproto3.Query{String: "select slot, pg_sleep(60)"}})

	expectPanic(t, done)
}

// panicChecker panics on every statement, as a bug in a rule would.
type panicChecker struct{}

func (panicChecker) Check(string, Settings) (*pgproto3.ErrorResponse, Gate) { panic("bug") }
func (panicChecker) CheckTooLong(int) *pgproto3.ErrorResponse               { panic("bug") }

// relayWith runs Relay with opts and a login that succeeds at once; done gets what it returns.
func relayWith(t *testing.T, opts Options) (client, pg net.Conn, done <-chan error) {
	t.Helper()
	client, proxyClient := tcpPair(t)
	pg, proxyServer := tcpPair(t)
	opts.Login = func(io.Writer, io.Reader, func(string, string)) error { return nil }
	ch := make(chan error, 1)
	go func() { ch <- Relay(proxyClient, proxyServer, opts) }()
	return client, pg, ch
}

// expectPanic waits for Relay to return a recovered panic.
func expectPanic(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if _, ok := errors.AsType[*safe.Panic](err); !ok {
			t.Fatalf("Relay returned %v; want the recovered panic", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Relay did not return")
	}
}

func TestRecordsASimpleQueryWithItsRowsAndTime(t *testing.T) {
	rec := make(chan Finished, 10)
	h := startWith(t, Options{Record: func(f Finished) { rec <- f }})

	h.send(&pgproto3.Query{String: "select 1"})
	h.serverGets(&pgproto3.Query{String: "select 1"})
	h.reply(&pgproto3.DataRow{Values: [][]byte{[]byte("1")}}, &pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'})

	f := expectFinished(t, rec)
	if f.SQL != "select 1" || f.Rows != 1 || f.Took <= 0 || f.Code != "" || f.Rejected || f.NotRun {
		t.Errorf("recorded %+v; want select 1, one row, a time", f)
	}
}

func TestRecordsAQuerysErrorCode(t *testing.T) {
	rec := make(chan Finished, 10)
	h := startWith(t, Options{Record: func(f Finished) { rec <- f }})

	h.send(&pgproto3.Query{String: "select 1/0"})
	h.serverGets(&pgproto3.Query{String: "select 1/0"})
	h.reply(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "22012", Message: "division by zero"}, &pgproto3.ReadyForQuery{TxStatus: 'I'})

	if f := expectFinished(t, rec); f.Code != "22012" || f.Message != "division by zero" || f.SQL != "select 1/0" {
		t.Errorf("recorded %+v; want the division error", f)
	}
}

func TestRecordsAMultiStatementQueryOnceWithEveryRow(t *testing.T) {
	rec := make(chan Finished, 10)
	h := startWith(t, Options{Record: func(f Finished) { rec <- f }})
	q := &pgproto3.Query{String: "update a set x = 1; update b set x = 1"}

	h.send(q)
	h.serverGets(q)
	h.reply(&pgproto3.CommandComplete{CommandTag: []byte("UPDATE 2")}, &pgproto3.CommandComplete{CommandTag: []byte("UPDATE 3")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'})

	if f := expectFinished(t, rec); f.Rows != 5 {
		t.Errorf("recorded %+v; want 5 rows", f)
	}
	expectNoFinished(t, rec)
}

func TestRecordsAnExecuteWithItsStatementsText(t *testing.T) {
	rec := make(chan Finished, 10)
	h := startWith(t, Options{Record: func(f Finished) { rec <- f }})
	parse := &pgproto3.Parse{Name: "s1", Query: "insert into t values ($1)"}
	bind := &pgproto3.Bind{DestinationPortal: "p1", PreparedStatement: "s1", Parameters: [][]byte{[]byte("7")}}

	h.send(parse, bind, &pgproto3.Execute{Portal: "p1"}, &pgproto3.Sync{})
	h.serverGets(parse, bind, &pgproto3.Execute{Portal: "p1"}, &pgproto3.Sync{})
	h.reply(&pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, &pgproto3.CommandComplete{CommandTag: []byte("INSERT 0 1")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'})

	if f := expectFinished(t, rec); f.SQL != parse.Query || f.Rows != 1 || f.Took <= 0 {
		t.Errorf("recorded %+v; want the insert, one row and a time", f)
	}
	expectNoFinished(t, rec)
}

func TestStatementsSharingASyncAreRecordedWithoutATime(t *testing.T) {
	rec := make(chan Finished, 10)
	h := startWith(t, Options{Record: func(f Finished) { rec <- f }})
	parse := &pgproto3.Parse{Query: "select 1"}

	h.send(parse, &pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Sync{})
	h.serverGets(parse, &pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Sync{})
	tag := &pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}
	h.reply(&pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, tag, &pgproto3.BindComplete{}, tag, &pgproto3.ReadyForQuery{TxStatus: 'I'})

	for range 2 {
		if f := expectFinished(t, rec); f.SQL != "select 1" || f.Took != 0 || f.Rows != 1 {
			t.Errorf("recorded %+v; want select 1 counted without a time of its own", f)
		}
	}
}

func TestRecordsAParseErrorAsNotRun(t *testing.T) {
	rec := make(chan Finished, 10)
	h := startWith(t, Options{Record: func(f Finished) { rec <- f }})
	parse := &pgproto3.Parse{Query: "selec 1"}

	h.send(parse, &pgproto3.Sync{})
	h.serverGets(parse, &pgproto3.Sync{})
	h.reply(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42601", Message: "syntax error"}, &pgproto3.ReadyForQuery{TxStatus: 'I'})

	if f := expectFinished(t, rec); f.SQL != "selec 1" || f.Code != "42601" || !f.NotRun {
		t.Errorf("recorded %+v; want the syntax error, not run", f)
	}
}

func TestRecordsTheProxysOwnRejection(t *testing.T) {
	rec := make(chan Finished, 10)
	h := startWith(t, Options{Check: fakeChecker{}, Record: func(f Finished) { rec <- f }, Login: loginReporting})

	h.send(&pgproto3.Query{String: "select bad"})
	h.clientGets(rejected, &pgproto3.ReadyForQuery{TxStatus: 'I'})

	if f := expectFinished(t, rec); f.SQL != "select bad" || f.Code != rejected.Code || !f.Rejected {
		t.Errorf("recorded %+v; want the proxy's rejection", f)
	}
}

func TestRecordsARejectionPostgresRaisesForTheProxy(t *testing.T) {
	rec := make(chan Finished, 10)
	h := startWith(t, Options{Check: fakeChecker{}, Record: func(f Finished) { rec <- f }, Login: loginReporting})

	// The first query is still in flight, so the second's rejection must come from Postgres, after it.
	h.send(&pgproto3.Query{String: "select 1"}, &pgproto3.Query{String: "select bad"})
	h.serverGets(&pgproto3.Query{String: "select 1"}, &pgproto3.Query{String: wantDo})
	h.reply(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}, &pgproto3.ReadyForQuery{TxStatus: 'I'},
		rejected, &pgproto3.ReadyForQuery{TxStatus: 'I'})

	if f := expectFinished(t, rec); f.SQL != "select 1" || f.Rejected {
		t.Errorf("first recorded %+v; want select 1", f)
	}
	if f := expectFinished(t, rec); f.SQL != "select bad" || f.Code != rejected.Code || !f.Rejected {
		t.Errorf("second recorded %+v; want the rejection under its own text", f)
	}
}

// loginReporting is the login start uses, which reports the settings a checked statement needs.
func loginReporting(_ io.Writer, _ io.Reader, report func(name, value string)) error {
	report("standard_conforming_strings", loginSettings.StandardConformingStrings)
	report("client_encoding", loginSettings.ClientEncoding)
	return nil
}

func expectFinished(t *testing.T, rec <-chan Finished) Finished {
	t.Helper()
	select {
	case f := <-rec:
		return f
	case <-time.After(2 * time.Second):
		t.Fatal("nothing recorded")
		return Finished{}
	}
}

func expectNoFinished(t *testing.T, rec <-chan Finished) {
	t.Helper()
	select {
	case f := <-rec:
		t.Errorf("recorded %+v; want nothing more", f)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestRecordsTheErrorPostgresGaveTheCostChecksExplain(t *testing.T) {
	for name, run := range map[string]func(h *harness){
		"query": func(h *harness) {
			h.send(&pgproto3.Query{String: "select plan from nowhere"})
			h.serverGets(&pgproto3.Query{String: explainPrefix + "select plan from nowhere"})
			h.reply(postgresError, &pgproto3.ReadyForQuery{TxStatus: 'I'})
		},
		"bind": func(h *harness) {
			parse := &pgproto3.Parse{Name: "s1", Query: "select plan from nowhere"}
			h.send(parse, &pgproto3.Bind{PreparedStatement: "s1"}, &pgproto3.Execute{}, &pgproto3.Sync{})
			h.serverGets(append([]encoder{parse}, explainBind(explainPrefix+parse.Query, nil, nil, nil)...)...)
			h.reply(&pgproto3.ParseComplete{}, &pgproto3.CloseComplete{}, &pgproto3.ParseComplete{}, postgresError)
			h.serverGets(&pgproto3.Sync{})
			h.reply(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec := make(chan Finished, 10)
			h := startWith(t, Options{Check: fakeChecker{}, Record: func(f Finished) { rec <- f }, Login: loginReporting})

			run(h)

			if f := expectFinished(t, rec); f.SQL != "select plan from nowhere" || f.Code != postgresError.Code || !f.NotRun || f.Rejected {
				t.Errorf("recorded %+v; want Postgres's error for the statement, which never ran", f)
			}
		})
	}
}

func TestEndsATransactionPastItsTimeoutEvenWhileAStatementRuns(t *testing.T) {
	a := newAdmitter()
	a.tx = 100 * time.Millisecond
	h := start(t, fakeChecker{admit: a})

	h.send(&pgproto3.Query{String: "begin slot"})
	h.serverGets(&pgproto3.Query{String: "begin slot"})
	h.reply(&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")}, &pgproto3.ReadyForQuery{TxStatus: 'T'})
	h.clientGets(&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")}, &pgproto3.ReadyForQuery{TxStatus: 'T'})
	h.send(&pgproto3.Query{String: "select slot, pg_sleep(60)"})
	h.serverGets(&pgproto3.Query{String: "select slot, pg_sleep(60)"})

	// Postgres 17's transaction_timeout ends the session with this code; closing the connection rolls the transaction back.
	h.clientGets(&pgproto3.ErrorResponse{Severity: "FATAL", SeverityUnlocalized: "FATAL", Code: "25P04",
		Message: "queryguard: terminating connection due to transaction timeout"})
	select {
	case <-h.done:
		if !errors.Is(h.err, ErrTransactionTimeout) {
			t.Errorf("Relay returned %v; want ErrTransactionTimeout", h.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Relay did not end the session")
	}
}

func TestATransactionThatEndsInTimeKeepsItsSession(t *testing.T) {
	a := newAdmitter()
	a.tx = 100 * time.Millisecond
	h := start(t, fakeChecker{admit: a})

	h.send(&pgproto3.Query{String: "begin slot"})
	h.serverGets(&pgproto3.Query{String: "begin slot"})
	h.reply(&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")}, &pgproto3.ReadyForQuery{TxStatus: 'T'})
	h.send(&pgproto3.Query{String: "commit"})
	h.serverGets(&pgproto3.Query{String: "commit"})
	h.reply(&pgproto3.CommandComplete{CommandTag: []byte("COMMIT")}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")}, &pgproto3.ReadyForQuery{TxStatus: 'T'},
		&pgproto3.CommandComplete{CommandTag: []byte("COMMIT")}, &pgproto3.ReadyForQuery{TxStatus: 'I'})

	time.Sleep(200 * time.Millisecond)
	h.serverGetsNothingBefore(&pgproto3.Query{String: "select 'still here'"})
}

func TestCancelsAReadPastItsRowCap(t *testing.T) {
	a := newAdmitter()
	a.maxRows = 2
	h := start(t, fakeChecker{admit: a})
	row := &pgproto3.DataRow{Values: [][]byte{[]byte("x")}}

	h.send(&pgproto3.Query{String: "select slot from big"})
	h.serverGets(&pgproto3.Query{String: "select slot from big"})
	h.reply(row, row, row)

	expect(t, h.cancels, struct{}{})
	h.reply(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "57014", Message: "canceling statement due to user request"},
		&pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(row, row, row, &pgproto3.ErrorResponse{Severity: "ERROR", Code: "54000",
		Message: "queryguard: canceling statement that returned more than 2 rows", Hint: "Add a LIMIT, or page through the rows."},
		&pgproto3.ReadyForQuery{TxStatus: 'I'})
	rowBytes, _ := row.Encode(nil)
	if got := <-a.returned; got != [2]int64{3, 3 * int64(len(rowBytes)-5)} {
		t.Errorf("returned %v; want 3 rows and their bytes", got)
	}
}

func TestCancelsAPreparedReadPastItsRowCap(t *testing.T) {
	a := newAdmitter()
	a.maxRows = 2
	h := start(t, fakeChecker{admit: a})
	row := &pgproto3.DataRow{Values: [][]byte{[]byte("x")}}
	parse := &pgproto3.Parse{Name: "s1", Query: "select slot from big"}

	h.send(parse, &pgproto3.Bind{PreparedStatement: "s1"}, &pgproto3.Execute{}, &pgproto3.Sync{})
	h.serverGets(parse, &pgproto3.Bind{PreparedStatement: "s1"}, &pgproto3.Execute{}, &pgproto3.Sync{})
	h.reply(&pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, row, row, row)

	expect(t, h.cancels, struct{}{})
}

func TestLeavesAReadAfterAnotherInTheSameSyncUncut(t *testing.T) {
	a := newAdmitter()
	a.maxRows = 2
	h := start(t, fakeChecker{admit: a})
	row := &pgproto3.DataRow{Values: [][]byte{[]byte("x")}}
	p1, p2 := &pgproto3.Parse{Name: "a", Query: "update orders set n = 1"}, &pgproto3.Parse{Name: "b", Query: "select slot from big"}

	// Both run in one implicit transaction, so cancelling the read would roll back the update.
	h.send(p1, &pgproto3.Bind{PreparedStatement: "a"}, &pgproto3.Execute{}, &pgproto3.Flush{})
	h.serverGets(p1, &pgproto3.Bind{PreparedStatement: "a"}, &pgproto3.Execute{}, &pgproto3.Flush{})
	h.reply(&pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, &pgproto3.CommandComplete{CommandTag: []byte("UPDATE 1")})
	h.clientGets(&pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, &pgproto3.CommandComplete{CommandTag: []byte("UPDATE 1")})
	h.send(p2, &pgproto3.Bind{PreparedStatement: "b"}, &pgproto3.Execute{}, &pgproto3.Sync{})
	h.serverGets(p2, &pgproto3.Bind{PreparedStatement: "b"}, &pgproto3.Execute{}, &pgproto3.Sync{})
	h.reply(&pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, row, row, row)

	expectNone(t, h.cancels, "cancel of a read sharing its implicit transaction with an update")
}

func TestHoldsTheNextStatementUntilACapsCancelIsDone(t *testing.T) {
	a := newAdmitter()
	a.maxRows = 2
	release := make(chan struct{})
	h := startWith(t, Options{Check: fakeChecker{admit: a}, Cancel: func() { <-release }})
	done := sync.OnceFunc(func() { close(release) })
	t.Cleanup(done)
	row := &pgproto3.DataRow{Values: [][]byte{[]byte("x")}}

	// The statement finishes before the cancel reaches Postgres, so the cancel could land on whatever runs next.
	h.send(&pgproto3.Query{String: "select slot from big"})
	h.serverGets(&pgproto3.Query{String: "select slot from big"})
	h.reply(row, row, row, &pgproto3.CommandComplete{CommandTag: []byte("SELECT 3")}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	expect(t, h.cancels, struct{}{})
	h.clientGets(row, row, row, &pgproto3.CommandComplete{CommandTag: []byte("SELECT 3")}, &pgproto3.ReadyForQuery{TxStatus: 'I'})

	h.send(&pgproto3.Query{String: "select 'next'"})
	h.pg.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, err := h.pg.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Postgres got %d bytes, %v, while the cancel was in flight; want nothing until it is done", n, err)
	}
	done()
	h.serverGets(&pgproto3.Query{String: "select 'next'"})
}

func TestLeavesAReadInATransactionUncut(t *testing.T) {
	a := newAdmitter()
	a.maxRows = 2
	h := start(t, fakeChecker{admit: a})
	h.begin()
	row := &pgproto3.DataRow{Values: [][]byte{[]byte("x")}}

	// Cancelling it would roll back the transaction's writes too.
	h.send(&pgproto3.Query{String: "select slot from big"})
	h.serverGets(&pgproto3.Query{String: "select slot from big"})
	h.reply(row, row, row, &pgproto3.CommandComplete{CommandTag: []byte("SELECT 3")}, &pgproto3.ReadyForQuery{TxStatus: 'T'})

	h.clientGets(row, row, row, &pgproto3.CommandComplete{CommandTag: []byte("SELECT 3")}, &pgproto3.ReadyForQuery{TxStatus: 'T'})
	expectNone(t, h.cancels, "cancel of a statement in a transaction")
	if got := <-a.returned; got[0] != 3 {
		t.Errorf("returned %v; want 3 rows", got)
	}
}

func TestCancelsAReadPastItsByteCap(t *testing.T) {
	a := newAdmitter()
	a.maxBytes = 100
	h := start(t, fakeChecker{admit: a})
	row := &pgproto3.DataRow{Values: [][]byte{make([]byte, 80)}}

	h.send(&pgproto3.Query{String: "select slot from big"})
	h.serverGets(&pgproto3.Query{String: "select slot from big"})
	h.reply(row, row)

	expect(t, h.cancels, struct{}{})
}

func TestTellsTheAdmissionWhichLimitItsStatementBroke(t *testing.T) {
	a := newAdmitter()
	a.timeout = 50 * time.Millisecond
	h := start(t, fakeChecker{admit: a})

	h.send(&pgproto3.Query{String: "select slot, pg_sleep(60)"})
	h.serverGets(&pgproto3.Query{String: "select slot, pg_sleep(60)"})
	expect(t, h.cancels, struct{}{})
	h.reply(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "57014", Message: "canceling statement due to user request"},
		&pgproto3.ReadyForQuery{TxStatus: 'I'})

	expect(t, a.broke, "57014")
}

func TestASessionsOwnCancelBreaksNoLimit(t *testing.T) {
	a := newAdmitter()
	h := start(t, fakeChecker{admit: a})

	h.send(&pgproto3.Query{String: "select slot, pg_sleep(60)"})
	h.serverGets(&pgproto3.Query{String: "select slot, pg_sleep(60)"})
	h.reply(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "57014", Message: "canceling statement due to user request"},
		&pgproto3.ReadyForQuery{TxStatus: 'I'})
	h.clientGets(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "57014", Message: "canceling statement due to user request"},
		&pgproto3.ReadyForQuery{TxStatus: 'I'})

	expectNone(t, a.broke, "a limit broken by a client's own cancel")
}
