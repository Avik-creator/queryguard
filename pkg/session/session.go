// Package session relays one client's messages to its server after login, checking each statement on the way.
package session

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgproto3"
)

// maxCheckedLen caps the Query and Parse messages read whole for checking; longer ones go to CheckTooLong.
const maxCheckedLen = 16 << 20

// bufSize matches Postgres's own 8 KB send buffer.
const bufSize = 8 << 10

// maxReplayed caps a Bind sent a second time to explain its statement; larger ones get a generic plan instead.
const maxReplayed = 1 << 20

// explainName names the proxy's own statement and portal for EXPLAIN.
const explainName = "queryguard_explain"

// EXPLAIN prefixes; positions in Postgres's errors count from the start of the prefixed text.
const (
	explainPrefix = "EXPLAIN (FORMAT JSON, VERBOSE) "
	genericPrefix = "EXPLAIN (FORMAT JSON, VERBOSE, GENERIC_PLAN) "
)

// errPlanTooLarge says the plan was longer than the proxy reads.
var errPlanTooLarge = errors.New("plan too large to read")

// Checker decides whether a statement may run.
type Checker interface {
	// Check returns the error to send instead of running sql, or nil, and the cost check to run just before it executes, or nil.
	Check(sql string, set Settings) (*pgproto3.ErrorResponse, CostCheck)
	// CheckTooLong decides on a statement of size bytes, too long to read whole.
	CheckTooLong(size int) *pgproto3.ErrorResponse
}

// CostCheck returns the error to send instead of running a statement, judged on its plan, which explain gets when needed.
type CostCheck func(explain Explain) *pgproto3.ErrorResponse

// Explain gets the plan of the statement about to run.
type Explain struct {
	Generic bool                   // the plan for any parameter values, used when the bound values are too large to send twice
	Run     func() (string, error) // EXPLAIN (FORMAT JSON, VERBOSE)'s output, or ErrNoPlan
}

// ErrNoPlan says Postgres gave no plan: it refused the statement, whose error the session passes on, or it is skipping to Sync.
var ErrNoPlan = errors.New("postgres gave no plan")

// Settings are the server settings that change how Postgres reads statement text; an empty field is unknown.
type Settings struct {
	StandardConformingStrings string // "off" makes a backslash in '…' an escape
	ClientEncoding            string // Postgres converts statements from it before parsing them
}

// Relay runs login, which passes each ParameterStatus to report, then relays messages both ways until either side
// closes; it closes both and returns the first error.
func Relay(client, server net.Conn, check Checker, login func(client io.Writer, server io.Reader, report func(name, value string)) error) error {
	s := &session{
		check:      check,
		clientIn:   bufio.NewReaderSize(client, bufSize),
		clientOut:  bufio.NewWriterSize(client, bufSize),
		serverIn:   bufio.NewReaderSize(server, bufSize),
		serverOut:  bufio.NewWriterSize(server, bufSize),
		ready:      make(chan struct{}),
		serverGone: make(chan struct{}),
	}
	var (
		once  sync.Once
		first error
	)
	stop := func(err error) {
		once.Do(func() {
			first = err
			client.Close()
			server.Close()
		})
	}
	var loops sync.WaitGroup
	loops.Go(func() { stop(s.fromClient()) })
	loops.Go(func() {
		defer close(s.serverGone)
		err := login(client, s.serverIn, func(name, value string) {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.report(name, value)
		})
		if err == nil {
			s.loggedIn()
		}
		close(s.ready)
		if err == nil {
			err = s.fromServer()
		}
		stop(err)
	})
	loops.Wait()
	return first
}

// session is the state shared by the two relay loops.
type session struct {
	check      Checker
	ready      chan struct{} // closed once login has ended
	serverGone chan struct{} // closed once nothing more is read from the server
	clientIn   *bufio.Reader
	serverIn   *bufio.Reader
	serverOut  *bufio.Writer // only fromClient writes to the server

	mu         sync.Mutex
	clientOut  *bufio.Writer // both loops write to the client, so only under mu
	status     byte          // transaction status from the last ReadyForQuery; 0 until login ends
	pending    []sent        // messages the server has yet to finish answering, oldest first
	skipping   bool          // the server ignores everything up to the next Sync after an extended-protocol error
	reported   Settings      // as last reported by the server
	explaining *explanation  // the proxy's EXPLAIN in flight, if any

	// Only fromClient uses these.
	inBatch    bool                 // extended-protocol messages went to the server since the last Sync
	discard    untilSync            // what to do with client messages after a rejected Parse
	statements map[string]statement // prepared statements with a cost check, by name
}

// sent is a message the server will answer.
type sent struct {
	typ byte
	how answer
}

// answer says where the server's answers to a message go.
type answer int

const (
	relayed  answer = iota // a client's message: to the client
	hidden                 // the proxy's DO block: only its error, to the client
	captured               // the proxy's EXPLAIN: to the statement waiting for its plan
)

// explanation collects the answers to the proxy's EXPLAIN.
type explanation struct {
	plan     strings.Builder         // the plan's rows
	err      *pgproto3.ErrorResponse // why Postgres refused the statement, if it did
	tooLarge bool
	done     chan struct{} // closed once Postgres has answered or skipped every EXPLAIN message
}

// statement is a prepared statement whose cost is checked when it is bound.
type statement struct {
	sql   string
	types []uint32 // parameter types from its Parse
	cost  CostCheck
	set   Settings // the settings Postgres read sql with, as far as the session knew them at its Parse
	plain bool     // sql has no backslash or non-ASCII byte, so every setting reads it the same
}

// untilSync says how fromClient handles client messages up to the next Sync.
type untilSync int

const (
	relayAll    untilSync = iota // nothing rejected
	answerSync                   // drop them and answer the Sync with ReadyForQuery itself
	forwardSync                  // drop them but send the Sync, since Postgres is raising the error
)

func (s *session) loggedIn() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = 'I'
}

// fromClient relays client messages to the server, checking each Query and Parse.
func (s *session) fromClient() error {
	for {
		// Flush only when the client has nothing more queued, so a pipeline goes out in one write.
		if s.clientIn.Buffered() == 0 {
			if err := s.serverOut.Flush(); err != nil {
				return err
			}
		}
		typ, n, err := readHeader(s.clientIn)
		if err != nil {
			return err
		}
		switch {
		case s.discard != relayAll:
			err = s.dropUntilSync(typ, n)
		case (typ == 'Q' || typ == 'P') && s.check != nil:
			// The client gets ReadyForQuery before loggedIn runs; waiting keeps a quick first query from seeing status 0.
			<-s.ready
			err = s.checkStatement(typ, n)
		case typ == 'B' && len(s.statements) > 0:
			err = s.checkBind(n)
		case typ == 'C' && len(s.statements) > 0:
			err = s.closeStatement(n)
		default:
			err = s.forward(typ, n)
		}
		if err != nil {
			return err
		}
	}
}

// checkStatement reads a Query or Parse message whole and forwards or rejects it.
func (s *session) checkStatement(typ byte, n int) error {
	if n > maxCheckedLen {
		if typ == 'P' {
			// The statement replaces any of the same name, unchecked.
			if head, err := s.clientIn.Peek(bufSize); err == nil {
				name, _, _ := bytes.Cut(head, []byte{0})
				delete(s.statements, string(name))
			}
		}
		if rej := s.check.CheckTooLong(n); rej != nil {
			if _, err := s.clientIn.Discard(n); err != nil {
				return unexpected(err)
			}
			return s.reject(typ, rej)
		}
		return s.forward(typ, n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(s.clientIn, body); err != nil {
		return unexpected(err)
	}
	// A malformed message goes on unchanged, for Postgres to refuse.
	if sql, ok := statementText(typ, body); ok {
		set := s.settings()
		rej, cost := s.check.Check(sql, set)
		switch {
		case rej != nil:
			return s.reject(typ, rej)
		case typ == 'P':
			s.prepare(body, cost, set)
		case cost != nil:
			if handled, err := s.checkQueryCost(sql, cost); handled || err != nil {
				return err
			}
		}
	}
	s.track(typ, relayed)
	writeHeader(s.serverOut, typ, n)
	_, err := s.serverOut.Write(body)
	return err
}

// settings returns the reported settings, or none while anything sent may still change them before sql is read.
func (s *session) settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Postgres reports changes just before ReadyForQuery, which an unsynced batch has yet to get.
	if len(s.pending) > 0 || s.inBatch {
		return Settings{}
	}
	return s.reported
}

// report records a ParameterStatus; the caller holds mu.
func (s *session) report(name, value string) {
	switch name {
	case "standard_conforming_strings":
		s.reported.StandardConformingStrings = value
	case "client_encoding":
		s.reported.ClientEncoding = value
	}
}

// prepare remembers a Parse's statement, read under set, for the cost check when it is bound.
func (s *session) prepare(body []byte, cost CostCheck, set Settings) {
	var p pgproto3.Parse
	if p.Decode(body) != nil {
		return
	}
	if cost == nil {
		delete(s.statements, p.Name)
		return
	}
	if s.statements == nil {
		s.statements = map[string]statement{}
	}
	plain := !strings.ContainsFunc(p.Query, func(r rune) bool { return r == '\\' || r >= utf8.RuneSelf })
	s.statements[p.Name] = statement{sql: p.Query, types: p.ParameterOIDs, cost: cost, set: set, plain: plain}
}

// closeStatement forgets a closed statement before passing the Close on.
func (s *session) closeStatement(n int) error {
	if body, err := s.clientIn.Peek(min(n, bufSize)); err == nil && len(body) > 0 && body[0] == 'S' {
		name, _, _ := bytes.Cut(body[1:], []byte{0})
		delete(s.statements, string(name))
	}
	return s.forward('C', n)
}

// checkQueryCost runs a simple query's cost check before the query is sent; handled says the client has its answer.
func (s *session) checkQueryCost(sql string, cost CostCheck) (handled bool, err error) {
	if s.failedTransaction() {
		return false, nil
	}
	var refused *pgproto3.ErrorResponse
	rej := cost(Explain{Run: func() (string, error) {
		var out string
		out, refused, err = s.explain(len(explainPrefix), &pgproto3.Query{String: explainPrefix + sql})
		return out, err
	}})
	switch {
	case lost(err):
		return true, err
	case refused != nil:
		// The query would have failed the same way; Postgres's ReadyForQuery went with the EXPLAIN, so the proxy sends one.
		return true, s.toClient(refused, &pgproto3.ReadyForQuery{TxStatus: s.statusNow()})
	case rej != nil:
		return true, s.reject('Q', rej)
	}
	return false, nil
}

// checkBind runs the cost check of the statement a Bind uses, explaining it with the Bind's values, or generically when they are large.
func (s *session) checkBind(n int) error {
	head, err := s.clientIn.Peek(min(n, bufSize))
	if err != nil {
		return unexpected(err)
	}
	_, rest, ok := bytes.Cut(head, []byte{0})
	name, rest, ok2 := bytes.Cut(rest, []byte{0})
	st, found := s.statements[string(name)]
	// EXPLAIN reads the text again, which only reads the same as at Parse under the same settings.
	sameReading := st.plain || (st.set != Settings{} && s.settings() == st.set)
	if !ok || !ok2 || !found || !sameReading || s.failedTransaction() {
		return s.forward('B', n)
	}

	var body []byte
	prefix, bind := explainPrefix, &pgproto3.Bind{DestinationPortal: explainName, PreparedStatement: explainName}
	if n <= maxReplayed {
		body = make([]byte, n)
		if _, err := io.ReadFull(s.clientIn, body); err != nil {
			return unexpected(err)
		}
		var b pgproto3.Bind
		if b.Decode(body) != nil {
			// A malformed message goes on unchanged, for Postgres to refuse.
			return s.send('B', body)
		}
		bind.ParameterFormatCodes, bind.Parameters = b.ParameterFormatCodes, b.Parameters
	} else {
		count, ok := paramCount(rest)
		if !ok {
			return s.forward('B', n)
		}
		// GENERIC_PLAN ignores the values, but Postgres still wants one for each parameter.
		prefix, bind.Parameters = genericPrefix, make([][]byte, count)
	}

	var refused *pgproto3.ErrorResponse
	rej := st.cost(Explain{Generic: prefix == genericPrefix, Run: func() (string, error) {
		var out string
		out, refused, err = s.explain(len(prefix),
			&pgproto3.Close{ObjectType: 'S', Name: explainName},
			&pgproto3.Parse{Name: explainName, Query: prefix + st.sql, ParameterOIDs: st.types},
			bind,
			&pgproto3.Execute{Portal: explainName},
			// Closing the statement closes its portal too.
			&pgproto3.Close{ObjectType: 'S', Name: explainName},
			&pgproto3.Flush{})
		return out, err
	}})
	if lost(err) {
		return err
	}
	if refused != nil || rej != nil {
		if body == nil {
			if _, err := s.clientIn.Discard(n); err != nil {
				return unexpected(err)
			}
		}
		if rej != nil {
			return s.reject('B', rej)
		}
		// Postgres now skips to Sync, as it would after the client's own Bind failed.
		s.discard = forwardSync
		return s.toClient(refused)
	}
	if body == nil {
		return s.forward('B', n)
	}
	return s.send('B', body)
}

// paramCount reads a Bind's parameter count from b, the body after its two names, when b holds it.
func paramCount(b []byte) (int, bool) {
	if len(b) < 2 {
		return 0, false
	}
	formats := 2 + 2*int(binary.BigEndian.Uint16(b))
	if len(b) < formats+2 {
		return 0, false
	}
	return int(binary.BigEndian.Uint16(b[formats:])), true
}

// explain sends the proxy's EXPLAIN and waits for every answer; with no plan it returns ErrNoPlan, and Postgres's error if it refused.
func (s *session) explain(shift int, msgs ...pgproto3.FrontendMessage) (string, *pgproto3.ErrorResponse, error) {
	var buf []byte
	var types []byte
	for _, m := range msgs {
		start := len(buf)
		var err error
		if buf, err = m.Encode(buf); err != nil {
			return "", nil, err
		}
		types = append(types, buf[start])
	}
	e := &explanation{done: make(chan struct{})}
	s.mu.Lock()
	if s.skipping {
		s.mu.Unlock()
		return "", nil, ErrNoPlan
	}
	s.explaining = e
	for _, t := range types {
		if t != 'H' {
			s.pending = append(s.pending, sent{typ: t, how: captured})
		}
	}
	s.mu.Unlock()
	s.inBatch = s.inBatch || slices.ContainsFunc(types, func(t byte) bool { return t != 'Q' && t != 'H' })
	if _, err := s.serverOut.Write(buf); err != nil {
		return "", nil, err
	}
	if err := s.serverOut.Flush(); err != nil {
		return "", nil, err
	}

	select {
	case <-e.done:
	case <-s.serverGone:
		return "", nil, net.ErrClosed
	}
	switch {
	case e.err != nil:
		// The error points into the prefixed text; shift moves it back to the client's own.
		if e.err.Position > int32(shift) {
			e.err.Position -= int32(shift)
		}
		return "", e.err, ErrNoPlan
	case e.tooLarge:
		return "", nil, errPlanTooLarge
	case e.plan.Len() == 0:
		return "", nil, ErrNoPlan
	}
	return e.plan.String(), nil, nil
}

// lost reports whether err from explain means the session is over, rather than that there is no plan.
func lost(err error) bool {
	return err != nil && !errors.Is(err, ErrNoPlan) && !errors.Is(err, errPlanTooLarge)
}

// toClient writes msgs to the client and flushes them.
func (s *session) toClient(msgs ...pgproto3.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := writeMessages(s.clientOut, msgs...); err != nil {
		return err
	}
	return s.clientOut.Flush()
}

func (s *session) statusNow() byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// failedTransaction reports whether the client's transaction has failed, so every statement fails before it is planned.
func (s *session) failedTransaction() bool { return s.statusNow() == 'E' }

// send passes a message already read whole to the server.
func (s *session) send(typ byte, body []byte) error {
	s.track(typ, relayed)
	writeHeader(s.serverOut, typ, len(body))
	_, err := s.serverOut.Write(body)
	return err
}

// forward streams one client message to the server.
func (s *session) forward(typ byte, n int) error {
	s.track(typ, relayed)
	writeHeader(s.serverOut, typ, n)
	return copyBody(s.serverOut, s.clientIn, n)
}

// reject answers a rejected Query or Parse itself when nothing is in flight, and otherwise makes Postgres raise the error.
func (s *session) reject(typ byte, rej *pgproto3.ErrorResponse) error {
	s.mu.Lock()
	if s.status == 'I' && len(s.pending) == 0 && !s.inBatch {
		defer s.mu.Unlock()
		buf, err := rej.Encode(nil)
		if err != nil {
			return err
		}
		if typ == 'Q' {
			buf, _ = (&pgproto3.ReadyForQuery{TxStatus: s.status}).Encode(buf)
		} else {
			s.discard = answerSync
		}
		if _, err := s.clientOut.Write(buf); err != nil {
			return err
		}
		return s.clientOut.Flush()
	}
	s.mu.Unlock()

	// The error must come after Postgres's answers to what is in flight and must fail its transaction, so Postgres raises it.
	do := doBlock(rej)
	if typ == 'Q' {
		s.track('Q', relayed)
		return writeMessages(s.serverOut, &pgproto3.Query{String: do})
	}
	s.discard = forwardSync
	// The DO block takes the place of the unnamed statement.
	delete(s.statements, "")
	for _, t := range []byte{'P', 'B', 'E'} {
		s.track(t, hidden)
	}
	return writeMessages(s.serverOut, &pgproto3.Parse{Query: do}, &pgproto3.Bind{}, &pgproto3.Execute{})
}

// dropUntilSync drops client messages after a rejected Parse, as Postgres skips them after an error.
func (s *session) dropUntilSync(typ byte, n int) error {
	switch typ {
	case 'X':
		return s.forward(typ, n)
	case 'S':
		mode := s.discard
		s.discard = relayAll
		if mode == forwardSync {
			return s.forward(typ, n)
		}
		if _, err := s.clientIn.Discard(n); err != nil {
			return unexpected(err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := writeMessages(s.clientOut, &pgproto3.ReadyForQuery{TxStatus: s.status}); err != nil {
			return err
		}
		return s.clientOut.Flush()
	}
	_, err := s.clientIn.Discard(n)
	return unexpected(err)
}

// track records a message on its way to the server.
func (s *session) track(typ byte, how answer) {
	switch typ {
	case 'S':
		s.inBatch = false
	case 'P', 'B', 'D', 'E', 'C':
		s.inBatch = true
	}
	if !strings.ContainsRune("QFPBDECS", rune(typ)) {
		// Flush, Terminate, copy data and password messages get no answer of their own.
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if typ == 'S' {
		s.skipping = false
	} else if s.skipping {
		return
	}
	s.pending = append(s.pending, sent{typ: typ, how: how})
}

// fromServer relays server messages to the client, dropping answers to the proxy's own hidden messages.
func (s *session) fromServer() error {
	for {
		if s.serverIn.Buffered() == 0 {
			s.mu.Lock()
			err := s.clientOut.Flush()
			s.mu.Unlock()
			if err != nil {
				return err
			}
		}
		typ, n, err := readHeader(s.serverIn)
		if err != nil {
			return err
		}
		if err := s.relayAnswer(typ, n); err != nil {
			return err
		}
	}
}

// relayAnswer passes one server message on, holding mu so a rejection can't land between it and its effect on pending.
func (s *session) relayAnswer(typ byte, n int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.endExplaining()
	if typ == 'Z' && n > 0 {
		status, err := s.serverIn.Peek(1)
		if err != nil {
			return unexpected(err)
		}
		s.status = status[0]
	}
	// A longer ParameterStatus can't be one of the short settings report looks for.
	if typ == 'S' && n <= bufSize {
		body, err := s.serverIn.Peek(n)
		if err != nil {
			return unexpected(err)
		}
		if name, rest, ok := bytes.Cut(body, []byte{0}); ok {
			value, _, _ := bytes.Cut(rest, []byte{0})
			s.report(string(name), string(value))
		}
	}
	switch how := s.answered(typ); {
	case how == captured:
		return s.capture(typ, n)
	case how == hidden && typ != 'E':
		_, err := s.serverIn.Discard(n)
		return unexpected(err)
	}
	writeHeader(s.clientOut, typ, n)
	return copyBody(s.clientOut, s.serverIn, n)
}

// capture keeps the plan and any error from the answers to the proxy's EXPLAIN; the caller holds mu.
func (s *session) capture(typ byte, n int) error {
	e := s.explaining
	if e == nil || (typ != 'D' && typ != 'E') || n > maxCheckedLen {
		if e != nil && typ == 'D' {
			e.tooLarge = true
		}
		_, err := s.serverIn.Discard(n)
		return unexpected(err)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(s.serverIn, body); err != nil {
		return unexpected(err)
	}
	if typ == 'E' {
		var refused pgproto3.ErrorResponse
		if refused.Decode(body) == nil && e.err == nil {
			e.err = &refused
		}
		return nil
	}
	var row pgproto3.DataRow
	if row.Decode(body) == nil && len(row.Values) > 0 {
		e.plan.Write(row.Values[0])
	}
	return nil
}

// endExplaining wakes the statement waiting for its plan once no EXPLAIN message awaits an answer; the caller holds mu.
func (s *session) endExplaining() {
	if s.explaining != nil && !slices.ContainsFunc(s.pending, func(p sent) bool { return p.how == captured }) {
		close(s.explaining.done)
		s.explaining = nil
	}
}

// answered matches a server message to the oldest pending message and returns where it goes.
func (s *session) answered(typ byte) answer {
	// Notices, parameter changes and notifications can arrive at any time.
	if len(s.pending) == 0 || typ == 'N' || typ == 'S' || typ == 'A' {
		return relayed
	}
	head := s.pending[0]
	if !finishes(head.typ, typ) {
		return head.how
	}
	s.pending = s.pending[1:]
	if typ == 'E' && head.typ != 'Q' && head.typ != 'F' && head.typ != 'S' {
		// After an extended-protocol error Postgres ignores everything up to the next Sync.
		if i := slices.IndexFunc(s.pending, func(p sent) bool { return p.typ == 'S' }); i >= 0 {
			s.pending = s.pending[i:]
		} else {
			s.pending = s.pending[:0]
			s.skipping = true
		}
	}
	return head.how
}

// finishes reports whether a server message of type reply is the last answer to a client message of type msg.
func finishes(msg, reply byte) bool {
	switch msg {
	case 'Q', 'F', 'S':
		return reply == 'Z'
	case 'P':
		return reply == '1' || reply == 'E'
	case 'B':
		return reply == '2' || reply == 'E'
	case 'C':
		return reply == '3' || reply == 'E'
	case 'D':
		return reply == 'T' || reply == 'n' || reply == 'E'
	case 'E':
		return reply == 'C' || reply == 'I' || reply == 's' || reply == 'E'
	}
	return false
}

// statementText returns the SQL in a Query (text\0) or Parse (name\0 text\0 …) body.
func statementText(typ byte, body []byte) (string, bool) {
	if typ == 'P' {
		var ok bool
		if _, body, ok = bytes.Cut(body, []byte{0}); !ok {
			return "", false
		}
	}
	sql, _, ok := bytes.Cut(body, []byte{0})
	return string(sql), ok
}

// doBlock raises e inside Postgres; each text is quoted twice, once for its literal and once for the DO body.
func doBlock(e *pgproto3.ErrorResponse) string {
	body := "BEGIN RAISE EXCEPTION USING ERRCODE = " + literal(e.Code) + ", MESSAGE = " + literal(e.Message)
	if e.Detail != "" {
		body += ", DETAIL = " + literal(e.Detail)
	}
	if e.Hint != "" {
		body += ", HINT = " + literal(e.Hint)
	}
	return "DO " + literal(body+"; END")
}

// literal quotes s as an SQL string, dropping backslashes and control characters, whose meaning depends on server settings.
func literal(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\\' || r < ' ' || r == 0x7f {
			return -1
		}
		return r
	}, s)
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// readHeader reads a message's type and the length of its body.
func readHeader(r *bufio.Reader) (typ byte, n int, err error) {
	head, err := r.Peek(5)
	if err != nil {
		if len(head) > 0 {
			return 0, 0, unexpected(err)
		}
		return 0, 0, err
	}
	size := binary.BigEndian.Uint32(head[1:])
	if size < 4 {
		return 0, 0, fmt.Errorf("message %q has length %d, below 4", head[0], size)
	}
	typ = head[0]
	r.Discard(5)
	return typ, int(size) - 4, nil
}

func writeHeader(w *bufio.Writer, typ byte, n int) {
	var head [5]byte
	head[0] = typ
	binary.BigEndian.PutUint32(head[1:], uint32(n+4))
	w.Write(head[:])
}

// copyBody streams n bytes from r to w through r's buffer, passing on whatever has arrived.
func copyBody(w *bufio.Writer, r *bufio.Reader, n int) error {
	for n > 0 {
		if _, err := r.Peek(1); err != nil {
			return unexpected(err)
		}
		chunk, _ := r.Peek(min(n, r.Buffered()))
		if _, err := w.Write(chunk); err != nil {
			return err
		}
		r.Discard(len(chunk))
		n -= len(chunk)
	}
	return nil
}

func writeMessages(w *bufio.Writer, msgs ...pgproto3.Message) error {
	var buf []byte
	for _, m := range msgs {
		var err error
		if buf, err = m.Encode(buf); err != nil {
			return err
		}
	}
	_, err := w.Write(buf)
	return err
}

// unexpected turns io.EOF inside a message into io.ErrUnexpectedEOF.
func unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
