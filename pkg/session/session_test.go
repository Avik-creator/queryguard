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

// fakeChecker rejects statements with "bad", and costs those with "plan", rejecting plans with "big".
type fakeChecker struct {
	allowTooLong bool
	seen         chan<- Settings // gets the settings of each checked statement, when set
	generic      chan<- bool     // gets whether each plan explained was generic, when set
}

func (c fakeChecker) Check(sql string, set Settings) (*pgproto3.ErrorResponse, CostCheck) {
	if c.seen != nil {
		c.seen <- set
	}
	switch {
	case strings.Contains(sql, "bad"):
		return rejected, nil
	case !strings.Contains(sql, "plan"):
		return nil, nil
	}
	return nil, func(e Explain) *pgproto3.ErrorResponse {
		out, _ := e.Run()
		if c.generic != nil {
			c.generic <- e.Generic
		}
		if strings.Contains(out, "big") {
			return tooCostly
		}
		return nil
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
		Relay(proxyClient, proxyServer, check, func(_ io.Writer, _ io.Reader, report func(name, value string)) error {
			report("standard_conforming_strings", loginSettings.StandardConformingStrings)
			report("client_encoding", loginSettings.ClientEncoding)
			report("TimeZone", "UTC")
			return nil
		})
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
