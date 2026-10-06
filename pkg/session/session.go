// Package session relays one client's messages to its server after login, checking each statement on the way.
package session

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/Avik-creator/queryguard/internal/safe"
	"github.com/jackc/pgx/v5/pgproto3"
)

// maxCheckedLen caps the Query and Parse messages read whole for checking; longer ones go to CheckUnread.
const maxCheckedLen = 16 << 20

// maxTexts and maxTextBytes bound the statement texts and portals a session keeps for recording; past them it starts over.
const (
	maxTexts     = 4096
	maxTextBytes = 16 << 20
)

// maxMessageLen is Postgres's own cap on a message, MaxAllocSize - 1; a longer length is a broken or hostile peer.
const maxMessageLen = 0x3ffffffe

// bufSize matches Postgres's own 8 KB send buffer.
const bufSize = 8 << 10

// maxReplayed caps a Bind sent a second time to explain its statement; larger ones get a generic plan instead.
const maxReplayed = 1 << 20

// explainName names the proxy's own statement and portal for EXPLAIN; the random part keeps it off any name a client picks.
var explainName = "queryguard_explain_" + strings.ToLower(rand.Text())

// EXPLAIN prefixes; positions in Postgres's errors count from the start of the prefixed text.
const (
	explainPrefix = "EXPLAIN (FORMAT JSON, VERBOSE) "
	genericPrefix = "EXPLAIN (FORMAT JSON, VERBOSE, GENERIC_PLAN) "
)

// errPlanTooLarge says the plan was longer than the proxy reads.
var errPlanTooLarge = errors.New("plan too large to read")

// Checker decides whether a statement may run.
type Checker interface {
	// Check returns the error to send instead of running sql, or nil, and the gate to pass just before it executes, or nil.
	Check(sql string, set Settings) (*pgproto3.ErrorResponse, Gate)
	// CheckUnread decides on a message it can't read as SQL, saying why in a sentence whose part before any colon the client may see.
	CheckUnread(why string) *pgproto3.ErrorResponse
}

// Gate decides how a statement about to execute runs, waiting while ctx lasts; running says the session already holds a slot.
type Gate func(ctx context.Context, explain Explain, running bool) Admission

// Admission says whether and how a statement runs.
type Admission struct {
	Reject            *pgproto3.ErrorResponse // the error to send instead of running it
	Release           func()                  // frees the slot it took, once the server is idle; nil when it took none
	Timeout           time.Duration           // how long it may run before the proxy cancels it; 0 means no limit
	IdleInTransaction time.Duration           // how long the session may then sit idle in a transaction; 0 means no limit
	// TransactionTimeout is how long a transaction the statement is in, or opens, may last, idle or not; 0 means no limit.
	TransactionTimeout time.Duration
	// Ran is called once Postgres has answered the statement, with how long it took and whether it ended without an error; nil skips it.
	// took is 0 when another statement shares its Sync, since Postgres holds a pipeline's answers until then.
	Ran func(took time.Duration, finished bool)
	// MaxRows and MaxBytes cancel the statement, when it runs outside a transaction, once it has returned more rows or bytes of rows; 0 means no cap.
	MaxRows, MaxBytes int64
	// Returned is called once the statement ends with the rows and bytes of row data it returned; nil skips it.
	Returned func(rows, bytes int64)
	// Broke is called when the proxy cancelled the statement, for its timeout, a cap or another reason i gives; nil skips it.
	Broke func(i Interruption)
	// Settled is called once the session is next idle outside a transaction, so what the statement did is committed or undone.
	Settled func()
	// Idle is called once the server is next idle, whether or not the statement ran, as after a Bind without an Execute.
	Idle func()
}

// Explain gets the plan of the statement about to run.
type Explain struct {
	Generic bool                   // the plan for any parameter values, used when the bound values are too large to send twice
	Values  string                 // a digest of the bound values, which can change the plan; "" for a simple query, whose values are in its text
	Run     func() (string, error) // EXPLAIN (FORMAT JSON, VERBOSE)'s output, or ErrNoPlan
}

// ErrNoPlan says Postgres gave no plan: it refused the statement, whose error the session passes on, or it is skipping to Sync.
var ErrNoPlan = errors.New("postgres gave no plan")

// Settings are the server settings the checker needs; an empty field is unknown.
type Settings struct {
	StandardConformingStrings string // "off" makes a backslash in '…' an escape
	ClientEncoding            string // Postgres converts statements from it before parsing them
	ApplicationName           string // known even while statements are in flight, since it doesn't change how text reads
}

// reading returns only the settings that change how Postgres reads statement text.
func (s Settings) reading() Settings {
	return Settings{StandardConformingStrings: s.StandardConformingStrings, ClientEncoding: s.ClientEncoding}
}

// Options set up a session.
type Options struct {
	Check  Checker                                                                         // nil checks nothing
	Login  func(client io.Writer, server io.Reader, report func(name, value string)) error // relays the login, passing each ParameterStatus to report
	Cancel func()                                                                          // asks Postgres to cancel what the server connection runs; nil can't
	// Interrupt gets, as Relay starts, a func that cancels what the session runs with i as the reason, reporting whether it ran anything.
	Interrupt func(interrupt func(i Interruption) bool)
	// Record gets each statement once it is answered; it runs with the session's lock held, so it must not block. nil records nothing.
	Record func(Finished)
	// Drain, once closed, ends the session as soon as it is idle outside a transaction, telling the client to connect again; nil never does.
	Drain <-chan struct{}
}

// Finished is a statement Postgres, or the proxy, has answered.
type Finished struct {
	SQL      string        // its Query or Parse text
	Took     time.Duration // from when it went to Postgres to its answer; 0 when it shared a Sync with another, so has no time of its own
	Rows     int64         // from its CommandCompletes
	Code     string        // its error's SQLSTATE; "" when it succeeded
	Message  string        // its error's text
	Rejected bool          // the proxy refused it
	NotRun   bool          // it failed at Parse or Bind, before running
}

// Interruption is why the proxy cancelled a statement: the client gets Postgres's cancel error with these fields in its place.
type Interruption struct {
	Code    string // SQLSTATE
	Message string
	Hint    string // "" keeps Postgres's
}

// ErrDrained ends a session that went idle while the proxy was draining.
var ErrDrained = errors.New("session drained for a restart")

// ErrIdleInTransaction ends a session left idle in a transaction past its limit.
var ErrIdleInTransaction = errors.New("session idle in a transaction past its limit")

// ErrTransactionTimeout ends a session whose transaction lasted past its limit, as transaction_timeout does in Postgres 17.
var ErrTransactionTimeout = errors.New("transaction past its limit")

// Waits for the client to hang up: after watchDelay, a waiting statement checks the client every watchPoll.
const (
	watchDelay = 50 * time.Millisecond
	watchPoll  = 200 * time.Millisecond
)

// Relay runs the login, then relays messages both ways until either side closes; it closes both and returns the first error.
func Relay(client, server net.Conn, opts Options) error {
	login := opts.Login
	s := &session{
		check:      opts.Check,
		record:     opts.Record,
		cancel:     opts.Cancel,
		client:     client,
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
	s.stop = func(err error) {
		once.Do(func() {
			s.stopped.Store(true)
			first = err
			client.Close()
			server.Close()
		})
	}
	stop := s.stop
	if opts.Interrupt != nil {
		opts.Interrupt(s.interrupt)
	}
	finished := make(chan struct{})
	defer close(finished)
	if opts.Drain != nil {
		go func() {
			select {
			case <-opts.Drain:
			case <-finished:
				return
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			s.draining = true
			s.endIfDrained()
		}()
	}
	var loops sync.WaitGroup
	// A panic in either loop, or in anything they call, ends this session alone.
	loops.Go(func() {
		defer safe.Recover(stop)
		err := s.fromClient()
		// A client that leaves mid-statement leaves Postgres working for no one.
		if !s.stopped.Load() && s.busy() && s.cancel != nil {
			s.cancel()
		}
		stop(err)
	})
	loops.Go(func() {
		defer close(s.serverGone)
		defer safe.Recover(stop)
		err := login(client, s.serverIn, func(name, value string) {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.report(name, value)
		})
		if err == nil {
			s.loggedIn()
		}
		s.loginErr = err
		close(s.ready)
		if err == nil {
			err = s.fromServer()
		}
		stop(err)
	})
	loops.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopTimers()
	s.freeSlot()
	// Postgres rolls back what the session left open, so it has settled too.
	s.settle()
	return first
}

// session is the state shared by the two relay loops.
type session struct {
	check      Checker
	cancel     func()        // from Options
	client     net.Conn      // read deadlines on it let a waiting statement notice a hang-up
	stop       func(error)   // ends the session, closing both connections
	stopped    atomic.Bool   // stop has run
	ready      chan struct{} // closed once login has ended
	loginErr   error         // why login failed, set before ready is closed; nothing a client sends is checked before it logs in
	serverGone chan struct{} // closed once nothing more is read from the server
	clientIn   *bufio.Reader
	serverIn   *bufio.Reader
	serverOut  *bufio.Writer // only fromClient writes to the server

	mu             sync.Mutex
	clientOut      *bufio.Writer   // both loops write to the client, so only under mu
	status         byte            // transaction status from the last ReadyForQuery; 0 until login ends
	pending        []sent          // messages the server has yet to finish answering, oldest first
	skipping       bool            // the server ignores everything up to the next Sync after an extended-protocol error
	copyIn         bool            // the server takes COPY data, ignoring any Sync until CopyDone or CopyFail
	suspended      map[string]sent // by portal, the Execute that ran an admitted statement until its row limit, for the next to go on with
	reported       Settings        // as last reported by the server
	explaining     *explanation    // the proxy's EXPLAIN in flight, if any
	slot           func()          // frees the slot the session holds, if any
	admitting      bool            // a gate is running, so the server going idle keeps the slot the statement will need
	timeout        time.Duration   // the admitted statement's timeout, for the message that runs it
	idleLimit      time.Duration   // how long the session may sit idle in a transaction
	stmtTimer      *time.Timer     // cancels the running statement at its timeout
	stmtGen        int             // bumped each time the statement timer is set, so one firing late does nothing
	idleTimer      *time.Timer     // ends the session idle in a transaction too long
	txLimit        time.Duration   // how long a transaction may last
	txTimer        *time.Timer     // ends the session whose transaction lasts too long
	txGen          int             // bumped as each transaction ends, so a transaction timer firing late does nothing
	batchStart     time.Time       // when the first message since the last Query or Sync went, which is when a transaction its batch opens began
	batchOpen      bool            // a message went since the last Query or Sync
	idleGen        int             // bumped by each client message, so an idle timer firing late does nothing
	interrupted    *Interruption   // why the proxy cancelled the running statement, so Postgres's cancel error says so
	interruptedRan *hooks          // that statement's admission, told once the cancel lands
	cancelling     chan struct{}   // closed once the proxy's own cancel request is done; nil when none is in flight
	draining       bool            // the proxy is draining, so the session ends once it is idle outside a transaction
	settled        []func()        // from admissions, called once the session is idle outside a transaction
	idle           []func()        // what admitted statements want called once the server is next idle

	// Only fromClient uses these.
	inBatch    bool                 // extended-protocol messages went to the server since the last Sync
	batchRan   bool                 // an Execute went since the last Sync, so a later one shares its implicit transaction
	discard    untilSync            // what to do with client messages after a rejected Parse
	statements map[string]statement // prepared statements with a cost check, by name
	record     func(Finished)       // from Options
	text       string               // the statement text of the client message being handled, when recording
	rejecting  byte                 // while the proxy sends its rejection of text, the type of the message it refused; else 0
	texts      map[string]string    // every prepared statement's text, by name, when recording
	textBytes  int                  // the length of the texts
	portals    map[string]string    // the text of each portal's statement, by portal name, when recording
	ran        *hooks               // from the last admission, for the message that runs its statement
	ranOn      byte                 // that message: Q for a simple query, E for a bound statement
	ranPortal  string               // the portal an E must name to run it
	execPortal string               // the portal named by the Execute being sent
}

// sent is a message the server will answer.
type sent struct {
	typ      byte
	how      answer
	ran      *hooks        // what the admission of the statement it runs asked for, if anything
	timeout  time.Duration // how long the statement it runs may take; 0 means no limit
	portal   string        // the portal an Execute names
	resumed  bool          // it goes on with a portal an earlier Execute suspended, so its time isn't the statement's
	capped   bool          // ran's caps apply, since it went outside a transaction with nothing ahead of it
	data     [2]int64      // the rows and bytes of row data answered so far
	start    time.Time     // when it went to the server, if it is timed and nothing ran ahead of it
	batch    time.Time     // when the first message of its batch, up to a Query or Sync, went
	failed   bool          // Postgres answered with an error
	worked   bool          // Postgres answered with more than an EmptyQueryResponse, so a statement ran
	sql      string        // the statement it belongs to, when recording
	rejected bool          // it is the proxy's rejection of sql
	notRun   bool          // it is the proxy's rejection of sql at Parse or Bind
	reply    reply         // what Postgres's answers to it said so far
}

// resume makes m go on with the statement whose portal prev suspended.
func (m *sent) resume(prev sent) {
	m.ran, m.capped, m.data, m.resumed = prev.ran, prev.capped, prev.data, true
}

// hooks are what an admission asks of the message that runs its statement.
type hooks struct {
	ran               func(time.Duration, bool)
	returned          func(rows, bytes int64)
	broke             func(Interruption)
	maxRows, maxBytes int64
}

// reply is what a recorded message's answers said.
type reply struct {
	rows          int64
	code, message string
}

// add takes in one more answer.
func (r *reply) add(more reply) {
	r.rows += more.rows
	if r.code == "" {
		r.code, r.message = more.code, more.message
	}
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
	gate  Gate
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
	s.endIfDrained()
}

// awaitLogin waits for the login to end, first sending Postgres a password that came in the same write as the statement.
func (s *session) awaitLogin() error {
	select {
	case <-s.ready:
		return nil
	default:
	}
	if err := s.serverOut.Flush(); err != nil {
		return err
	}
	<-s.ready
	return nil
}

// recordRefused records the error Postgres gave the cost check's EXPLAIN as the statement's own, since it would have failed the same way.
func (s *session) recordRefused(refused *pgproto3.ErrorResponse) {
	if s.record != nil && s.text != "" {
		s.record(Finished{SQL: s.text, Code: refused.Code, Message: refused.Message, NotRun: true})
	}
}

// noteText sets text to the statement a Bind or Execute uses, and keeps track of which statement each portal runs.
func (s *session) noteText(typ byte, n int) {
	s.text = ""
	if !strings.ContainsRune("BEC", rune(typ)) {
		return
	}
	body, err := s.clientIn.Peek(min(n, bufSize))
	if err != nil {
		return
	}
	switch typ {
	case 'B':
		portal, rest, ok := bytes.Cut(body, []byte{0})
		name, _, ok2 := bytes.Cut(rest, []byte{0})
		if !ok || !ok2 {
			return
		}
		s.text = s.texts[string(name)]
		s.notePortal(string(portal), s.text)
	case 'E':
		portal, _, _ := bytes.Cut(body, []byte{0})
		s.text = s.portals[string(portal)]
	case 'C':
		if len(body) == 0 {
			return
		}
		name, _, _ := bytes.Cut(body[1:], []byte{0})
		if body[0] == 'S' {
			s.forgetText(string(name))
		} else {
			delete(s.portals, string(name))
		}
	}
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
		s.awaitCancel()
		s.clientSent()
		if s.record != nil {
			s.noteText(typ, n)
		}
		switch {
		case s.discard != relayAll:
			err = s.dropUntilSync(typ, n)
		case (typ == 'Q' || typ == 'P' || typ == 'F') && (s.check != nil || s.record != nil):
			if s.check != nil {
				// The client gets ReadyForQuery before loggedIn runs; waiting keeps a quick first query from seeing status 0.
				if err := s.awaitLogin(); err != nil {
					return err
				}
				if s.loginErr != nil {
					return s.loginErr
				}
			}
			if typ == 'F' {
				err = s.functionCall(n)
			} else {
				err = s.checkStatement(typ, n)
			}
		case typ == 'B' && len(s.statements) > 0:
			err = s.checkBind(n)
		case typ == 'E':
			err = s.execute(n)
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

// rememberText keeps a prepared statement's text for recording; past the bounds they start over, as DEALLOCATE ALL closes none.
func (s *session) rememberText(name, sql string) {
	s.forgetText(name)
	if len(s.texts) >= maxTexts || s.textBytes+len(sql) > maxTextBytes {
		clear(s.texts)
		s.textBytes = 0
	}
	if s.texts == nil {
		s.texts = map[string]string{}
	}
	s.texts[name] = sql
	s.textBytes += len(sql)
}

func (s *session) forgetText(name string) {
	s.textBytes -= len(s.texts[name])
	delete(s.texts, name)
}

// notePortal keeps which statement a portal runs; portals ended with their transaction are never closed, so past the bound they start over.
func (s *session) notePortal(portal, sql string) {
	if _, ok := s.portals[portal]; !ok && len(s.portals) >= maxTexts {
		clear(s.portals)
	}
	if s.portals == nil {
		s.portals = map[string]string{}
	}
	s.portals[portal] = sql
}

// checkStatement reads a Query or Parse message whole and forwards or rejects it.
func (s *session) checkStatement(typ byte, n int) error {
	if n > maxCheckedLen {
		if typ == 'P' {
			// The statement replaces any of the same name, unchecked and unrecorded.
			if head, err := s.clientIn.Peek(bufSize); err == nil {
				name, _, _ := bytes.Cut(head, []byte{0})
				delete(s.statements, string(name))
				s.forgetText(string(name))
			}
		}
		if s.check == nil {
			return s.forward(typ, n)
		}
		if rej := s.check.CheckUnread(fmt.Sprintf("It is too long to read: %d bytes.", n)); rej != nil {
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
	sql, ok := statementText(typ, body)
	if ok && s.record != nil {
		s.text = sql
		if typ == 'P' {
			name, _, _ := bytes.Cut(body, []byte{0})
			s.rememberText(string(name), sql)
		}
	}
	if ok && s.check != nil {
		set := s.settings()
		rej, gate := s.check.Check(sql, set)
		switch {
		case rej != nil:
			return s.reject(typ, rej)
		case typ == 'P':
			s.prepare(body, gate, set)
		case gate != nil:
			if handled, err := s.checkQueryCost(sql, gate); handled || err != nil {
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
		return Settings{ApplicationName: s.reported.ApplicationName}
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
	case "application_name":
		s.reported.ApplicationName = value
	}
}

// prepare remembers a Parse's statement, read under set, for the cost check when it is bound.
func (s *session) prepare(body []byte, gate Gate, set Settings) {
	var p pgproto3.Parse
	if p.Decode(body) != nil {
		return
	}
	if gate == nil {
		delete(s.statements, p.Name)
		return
	}
	if s.statements == nil {
		s.statements = map[string]statement{}
	}
	plain := !strings.ContainsFunc(p.Query, func(r rune) bool { return r == '\\' || r >= utf8.RuneSelf })
	s.statements[p.Name] = statement{sql: p.Query, types: p.ParameterOIDs, gate: gate, set: set.reading(), plain: plain}
}

// closeStatement forgets a closed statement before passing the Close on.
func (s *session) closeStatement(n int) error {
	if body, err := s.clientIn.Peek(min(n, bufSize)); err == nil && len(body) > 0 && body[0] == 'S' {
		name, _, _ := bytes.Cut(body[1:], []byte{0})
		delete(s.statements, string(name))
	}
	return s.forward('C', n)
}

// functionCall decides on a fast-path function call, which names its function by number and so can't be checked.
func (s *session) functionCall(n int) error {
	if s.check == nil {
		return s.forward('F', n)
	}
	rej := s.check.CheckUnread("It is a fast-path function call, which names its function only by number.")
	if rej == nil {
		return s.forward('F', n)
	}
	if _, err := s.clientIn.Discard(n); err != nil {
		return unexpected(err)
	}
	// Postgres answers a function call as it does a simple query, with ReadyForQuery.
	return s.reject('Q', rej)
}

// checkQueryCost runs a simple query's cost check before the query is sent; handled says the client has its answer.
func (s *session) checkQueryCost(sql string, gate Gate) (handled bool, err error) {
	if s.failedTransaction() {
		return false, nil
	}
	var refused *pgproto3.ErrorResponse
	rej := s.admit(gate, 'Q', Explain{Run: func() (string, error) {
		var out string
		out, refused, err = s.explain(len(explainPrefix), &pgproto3.Query{String: explainPrefix + sql})
		return out, err
	}})
	switch {
	case lost(err):
		return true, err
	case refused != nil:
		// The query would have failed the same way; Postgres's ReadyForQuery went with the EXPLAIN, so the proxy sends one.
		s.recordRefused(refused)
		s.ran, s.timeout = nil, 0
		return true, s.readyForQuery(refused)
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
	portal, rest, ok := bytes.Cut(head, []byte{0})
	name, rest, ok2 := bytes.Cut(rest, []byte{0})
	st, found := s.statements[string(name)]
	// EXPLAIN reads the text again, which only reads the same as at Parse under the same settings.
	if !ok || !ok2 || !found || s.failedTransaction() {
		if string(portal) == s.ranPortal {
			// The portal now holds another statement, so the admitted one's Execute won't come.
			s.ran, s.timeout = nil, 0
		}
		return s.forward('B', n)
	}
	s.ranPortal = string(portal)
	if !st.plain && (st.set == Settings{} || s.settings().reading() != st.set) {
		// The statement still takes its slot and budget, judged without a plan.
		if rej := s.admit(st.gate, 'E', Explain{}); rej != nil {
			if _, err := s.clientIn.Discard(n); err != nil {
				return unexpected(err)
			}
			return s.reject('B', rej)
		}
		return s.forward('B', n)
	}

	var body []byte
	var values string
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
		// What follows the portal and statement names is the formats and values.
		_, formats, _ := bytes.Cut(body[len(portal)+1:], []byte{0})
		digest := sha256.Sum256(formats)
		values = string(digest[:])
	} else {
		count, ok := paramCount(rest)
		if !ok {
			return s.forward('B', n)
		}
		// GENERIC_PLAN ignores the values, but Postgres still wants one for each parameter.
		prefix, bind.Parameters = genericPrefix, make([][]byte, count)
	}

	var refused *pgproto3.ErrorResponse
	rej := s.admit(st.gate, 'E', Explain{Generic: prefix == genericPrefix, Values: values, Run: func() (string, error) {
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
		s.recordRefused(refused)
		return s.toClient(refused)
	}
	if body == nil {
		return s.forward('B', n)
	}
	return s.send('B', body)
}

// execute forwards an Execute, which runs the admitted statement only if it names that statement's portal.
func (s *session) execute(n int) error {
	head, err := s.clientIn.Peek(min(n, bufSize))
	if err != nil {
		return unexpected(err)
	}
	portal, _, _ := bytes.Cut(head, []byte{0})
	s.execPortal = string(portal)
	if string(portal) != s.ranPortal {
		// Another portal runs first; the admitted statement's Execute is still to come.
		ran, timeout := s.ran, s.timeout
		s.ran, s.timeout = nil, 0
		defer func() { s.ran, s.timeout = ran, timeout }()
	}
	return s.forward('E', n)
}

// admit passes gate for a statement about to run with message on, keeps the slot and limits it gives, and returns the error to send instead.
func (s *session) admit(gate Gate, on byte, e Explain) *pgproto3.ErrorResponse {
	s.ran, s.timeout = nil, 0
	s.mu.Lock()
	running := s.slot != nil
	s.admitting = true
	s.mu.Unlock()

	ctx, done := s.waitContext()
	a := gate(ctx, e, running)
	done()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.admitting = false
	if a.Release != nil {
		s.slot = a.Release
	}
	if a.Reject != nil {
		if len(s.pending) == 0 {
			// Nothing runs, so a slot kept for this statement goes back.
			s.freeSlot()
		}
		return a.Reject
	}
	s.timeout, s.idleLimit, s.txLimit = a.Timeout, a.IdleInTransaction, a.TransactionTimeout
	s.ran, s.ranOn = nil, on
	if a.Ran != nil || a.Returned != nil || a.Broke != nil || a.MaxRows > 0 || a.MaxBytes > 0 {
		s.ran = &hooks{ran: a.Ran, returned: a.Returned, broke: a.Broke, maxRows: a.MaxRows, maxBytes: a.MaxBytes}
	}
	if a.Settled != nil {
		s.settled = append(s.settled, a.Settled)
	}
	if a.Idle != nil {
		s.idle = append(s.idle, a.Idle)
	}
	return nil
}

// waitContext returns a context ended by a client hang-up or a lost server, and the func to call before reading the client again.
func (s *session) waitContext() (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		defer safe.Recover(func(err error) {
			cancel()
			s.stop(err)
		})
		// Most gates return at once, and only a statement that waits needs its client watched.
		select {
		case <-ctx.Done():
			return
		case <-s.serverGone:
			cancel()
			return
		case <-time.After(watchDelay):
		}
		for ctx.Err() == nil {
			// Peeking reads what the client sends into the buffer without taking it, and sees a hang-up as an error.
			if s.clientIn.Buffered() == 0 {
				s.client.SetReadDeadline(time.Now().Add(watchPoll))
				if _, err := s.clientIn.Peek(1); err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
					cancel()
					return
				}
			}
			select {
			case <-s.serverGone:
				cancel()
				return
			case <-ctx.Done():
				return
			case <-time.After(watchPoll / 4):
			}
		}
	}()
	return ctx, func() {
		cancel()
		// A deadline in the past wakes a Peek in progress.
		s.client.SetReadDeadline(time.Now())
		<-watched
		s.client.SetReadDeadline(time.Time{})
	}
}

// statementTimeout is why a statement past its timeout was cancelled.
var statementTimeout = Interruption{Code: "57014", Message: "queryguard: canceling statement due to statement timeout"}

// timeStatement sets the statement timer to cancel what runs after d, or stops it when d is 0; the caller holds mu.
func (s *session) timeStatement(d time.Duration) {
	s.stmtGen++
	if s.stmtTimer != nil {
		s.stmtTimer.Stop()
	}
	if d <= 0 {
		return
	}
	gen := s.stmtGen
	s.stmtTimer = time.AfterFunc(d, func() {
		defer safe.Recover(s.stop)
		s.statementTimedOut(gen)
	})
}

// statementTimedOut cancels the statement running past its timeout, unless the timer was set again since it started.
func (s *session) statementTimedOut(gen int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if gen == s.stmtGen {
		s.interruptLocked(statementTimeout)
	}
}

// interrupt cancels what the session runs, with i as the reason the client is given, and reports whether it ran anything.
func (s *session) interrupt(i Interruption) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.interruptLocked(i)
}

// interruptLocked is interrupt for a caller that holds mu.
func (s *session) interruptLocked(i Interruption) bool {
	busy := len(s.pending) > 0 && s.cancel != nil
	if busy {
		s.interrupted, s.interruptedRan = &i, s.running()
		s.cancelServer()
	}
	return busy
}

// running returns the admission hooks of the statement Postgres runs now, the first Query or Execute in flight; the caller holds mu.
func (s *session) running() *hooks {
	for _, p := range s.pending {
		if p.typ == 'Q' || p.typ == 'E' {
			return p.ran
		}
	}
	return nil
}

// clientSent stops the idle-in-transaction timer, since the client has sent something.
func (s *session) clientSent() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idleGen++
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
}

// endIfDrained ends a draining session that is idle outside a transaction, as Postgres's shutdown ends idle sessions; the caller holds mu.
func (s *session) endIfDrained() {
	if !s.draining || s.status != 'I' || len(s.pending) > 0 || s.batchOpen || s.admitting {
		return
	}
	writeMessages(s.clientOut, &pgproto3.ErrorResponse{Severity: "FATAL", SeverityUnlocalized: "FATAL", Code: "57P01",
		Message: "queryguard: terminating connection because the proxy is restarting", Hint: "Connect again; another QueryGuard process takes new connections."})
	s.clientOut.Flush()
	s.stop(ErrDrained)
}

// becameIdle frees the slot, stops the statement timer and starts the idle-in-transaction one; the caller holds mu.
func (s *session) becameIdle() {
	s.timeStatement(0)
	s.interrupted = nil
	// The proxy's own EXPLAIN ends while the statement it is for is being admitted, which needs the slot.
	if s.admitting {
		return
	}
	s.freeSlot()
	for _, f := range s.idle {
		f()
	}
	s.idle = nil
	if s.status == 'I' {
		s.settle()
		s.endIfDrained()
	}
	if (s.status == 'T' || s.status == 'E') && s.idleLimit > 0 {
		gen := s.idleGen
		s.idleTimer = time.AfterFunc(s.idleLimit, func() {
			defer safe.Recover(s.stop)
			s.idleTimedOut(gen)
		})
	}
}

// idleTimedOut ends the session as idle_in_transaction_session_timeout does, unless the client sent something since.
func (s *session) idleTimedOut(gen int) {
	s.mu.Lock()
	if gen != s.idleGen || len(s.pending) > 0 || (s.status != 'T' && s.status != 'E') {
		s.mu.Unlock()
		return
	}
	// Closing the server connection makes Postgres roll the transaction back.
	if writeMessages(s.clientOut, &pgproto3.ErrorResponse{Severity: "FATAL", SeverityUnlocalized: "FATAL", Code: "25P03",
		Message: "queryguard: terminating connection due to idle-in-transaction timeout"}) == nil {
		s.clientOut.Flush()
	}
	s.mu.Unlock()
	s.stop(ErrIdleInTransaction)
}

// settle calls what waits for the session to be outside a transaction; the caller holds mu.
func (s *session) settle() {
	for _, f := range s.settled {
		f()
	}
	s.settled = nil
}

// freeSlot frees the slot the session holds, if any; the caller holds mu.
func (s *session) freeSlot() {
	if s.slot != nil {
		s.slot()
		s.slot = nil
	}
}

// transaction starts the transaction timer as one opens and stops it as one ends, given the status in a ReadyForQuery; the caller holds mu.
func (s *session) transaction(status byte) {
	switch {
	case status == 'I' && s.status != 'I':
		s.txGen++
		if s.txTimer != nil {
			s.txTimer.Stop()
			s.txTimer = nil
		}
	case status != 'I' && s.status == 'I' && s.txLimit > 0:
		gen := s.txGen
		// The ReadyForQuery answers the Query or Sync that ended the batch which opened the transaction.
		began := time.Now()
		if len(s.pending) > 0 {
			began = s.pending[0].batch
		}
		s.txTimer = time.AfterFunc(s.txLimit-time.Since(began), func() {
			defer safe.Recover(s.stop)
			s.transactionTimedOut(gen)
		})
	}
}

// transactionTimedOut ends the session as transaction_timeout does, unless its transaction has ended since.
func (s *session) transactionTimedOut(gen int) {
	s.mu.Lock()
	if gen != s.txGen || s.status == 'I' {
		s.mu.Unlock()
		return
	}
	// Closing the server connection makes Postgres roll the transaction back, and stops a statement still running in it.
	if writeMessages(s.clientOut, &pgproto3.ErrorResponse{Severity: "FATAL", SeverityUnlocalized: "FATAL", Code: "25P04",
		Message: "queryguard: terminating connection due to transaction timeout"}) == nil {
		s.clientOut.Flush()
	}
	s.mu.Unlock()
	s.stop(ErrTransactionTimeout)
}

// stopTimers stops the session's timers; the caller holds mu.
func (s *session) stopTimers() {
	for _, t := range []*time.Timer{s.stmtTimer, s.idleTimer, s.txTimer} {
		if t != nil {
			t.Stop()
		}
	}
}

// busy reports whether Postgres is working on something the client sent.
func (s *session) busy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending) > 0
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

// readyForQuery sends the client msgs and a ReadyForQuery of the proxy's own, then does what Postgres's would: the server is idle.
func (s *session) readyForQuery(msgs ...pgproto3.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := writeMessages(s.clientOut, append(msgs, &pgproto3.ReadyForQuery{TxStatus: s.status})...); err != nil {
		return err
	}
	if err := s.clientOut.Flush(); err != nil {
		return err
	}
	if len(s.pending) == 0 && !s.admitting {
		s.becameIdle()
	}
	return nil
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
	s.rejecting = typ
	defer func() { s.rejecting = 0 }()
	s.mu.Lock()
	if s.status == 'I' && len(s.pending) == 0 && !s.inBatch {
		defer s.mu.Unlock()
		if s.record != nil && s.text != "" {
			s.record(Finished{SQL: s.text, Code: rej.Code, Message: rej.Message, Rejected: true, NotRun: typ == 'P' || typ == 'B'})
		}
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
		if err := s.clientOut.Flush(); err != nil {
			return err
		}
		if typ == 'Q' {
			s.becameIdle()
		}
		return nil
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
		return s.readyForQuery()
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
	if typ == 'S' || typ == 'c' || typ == 'f' {
		s.mu.Lock()
		copying := s.copyIn
		s.copyIn = s.copyIn && typ == 'S'
		s.mu.Unlock()
		if copying && typ == 'S' {
			return
		}
	}
	if !strings.ContainsRune("QFPBDECS", rune(typ)) {
		// Flush, Terminate, copy data and password messages get no answer of their own.
		return
	}
	m := sent{typ: typ, how: how}
	if typ == 'E' {
		m.portal = s.execPortal
	}
	if typ == s.ranOn && how == relayed {
		m.ran, m.timeout = s.ran, s.timeout
	}
	// The proxy's rejection through Postgres runs as a hidden Execute, which is what answers for the rejected statement.
	if s.record != nil && strings.ContainsRune("QPBE", rune(typ)) && (how == relayed || (how == hidden && typ == 'E')) {
		m.sql, m.rejected = s.text, s.rejecting != 0
		// The hidden Execute raising a rejected Parse's or Bind's error stands for a statement that never ran.
		m.notRun = s.rejecting == 'P' || s.rejecting == 'B'
	}
	if typ == s.ranOn || typ == 'S' {
		// A statement bound but never executed before Sync reports nothing.
		s.ran, s.timeout = nil, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if typ == 'S' {
		s.skipping = false
	} else if s.skipping {
		return
	}
	if !s.batchOpen {
		s.batchStart, s.batchOpen = time.Now(), true
	}
	m.batch = s.batchStart
	if typ == 'Q' || typ == 'S' {
		s.batchOpen = false
	}
	// Postgres sends a pipeline's answers together at Sync, so a statement behind another running one can't be timed on its own.
	timed := (m.ran != nil && m.ran.ran != nil) || (m.sql != "" && (typ == 'Q' || typ == 'E'))
	// A statement in a transaction isn't cut short, since cancelling it would roll back what the transaction already did.
	m.capped = m.ran != nil && s.status == 'I' && !s.batchRan &&
		!slices.ContainsFunc(s.pending, func(p sent) bool { return p.typ == 'Q' || p.typ == 'E' || p.typ == 'S' })
	switch typ {
	case 'E':
		s.batchRan = true
	case 'S':
		s.batchRan = false
	}
	if timed && !slices.ContainsFunc(s.pending, func(p sent) bool { return p.typ == 'Q' || p.typ == 'E' }) {
		m.start = time.Now()
	}
	if prev, ok := s.suspended[m.portal]; ok && typ == 'E' && m.ran == nil {
		delete(s.suspended, m.portal)
		m.resume(prev)
	}
	// The timeout counts from when the statement runs, which is now unless another runs ahead of it.
	if m.timeout > 0 && !slices.ContainsFunc(s.pending, func(p sent) bool { return p.typ == 'Q' || p.typ == 'E' }) {
		s.timeStatement(m.timeout)
	}
	s.pending = append(s.pending, m)
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
	defer func() {
		if typ == 'Z' && len(s.pending) == 0 {
			s.becameIdle()
		}
	}()
	defer s.endExplaining()
	if typ == 'Z' && n > 0 {
		status, err := s.serverIn.Peek(1)
		if err != nil {
			return unexpected(err)
		}
		s.transaction(status[0])
		s.status = status[0]
		if s.status == 'I' {
			// A transaction's end closes its portals.
			clear(s.suspended)
		}
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
	var r reply
	if s.record != nil && (typ == 'C' || typ == 'E') && n <= bufSize {
		if body, err := s.serverIn.Peek(n); err == nil {
			r = readReply(typ, body)
		}
	}
	switch how := s.answered(typ, n, r); {
	case how == captured:
		return s.capture(typ, n)
	case how == hidden && typ != 'E':
		_, err := s.serverIn.Discard(n)
		return unexpected(err)
	case typ == 'E' && s.interrupted != nil && n <= maxCheckedLen:
		return s.relayInterrupted(n)
	}
	writeHeader(s.clientOut, typ, n)
	return copyBody(s.clientOut, s.serverIn, n)
}

// relayInterrupted passes on an error after the proxy's cancel, saying why if it is the cancel's error; the caller holds mu.
func (s *session) relayInterrupted(n int) error {
	body := make([]byte, n)
	if _, err := io.ReadFull(s.serverIn, body); err != nil {
		return unexpected(err)
	}
	var e pgproto3.ErrorResponse
	if e.Decode(body) != nil || e.Code != "57014" {
		writeHeader(s.clientOut, 'E', n)
		_, err := s.clientOut.Write(body)
		return err
	}
	i, h := s.interrupted, s.interruptedRan
	s.interrupted, s.interruptedRan = nil, nil
	if h != nil && h.broke != nil {
		h.broke(*i)
	}
	e.Code, e.Message, e.Hint = i.Code, i.Message, cmp.Or(i.Hint, e.Hint)
	return writeMessages(s.clientOut, &e)
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
func (s *session) answered(typ byte, n int, r reply) answer {
	// Notices, parameter changes and notifications can arrive at any time.
	if len(s.pending) == 0 || typ == 'N' || typ == 'S' || typ == 'A' {
		return relayed
	}
	head := s.pending[0]
	switch typ {
	case 'G':
		// Postgres ignores a Sync sent while it takes COPY data, as libpq sends one right after an extended-protocol COPY.
		s.copyIn = true
		i := 1
		for i < len(s.pending) && s.pending[i].typ == 'S' {
			i++
		}
		s.pending = slices.Delete(s.pending, 1, i)
	case 'Z':
		s.copyIn = false
	}
	if !finishes(head.typ, typ) {
		// A simple query's error comes before its ReadyForQuery.
		s.pending[0].failed = s.pending[0].failed || typ == 'E'
		s.pending[0].worked = s.pending[0].worked || typ != 'I'
		s.pending[0].reply.add(r)
		if typ == 'D' {
			s.returnedRow(&s.pending[0], n)
		}
		return head.how
	}
	s.pending = s.pending[1:]
	head.reply.add(r)
	if head.typ == 'Q' && !head.worked {
		// A query of only semicolons or comments ran nothing, which its ReadyForQuery doesn't say.
		typ = 'I'
	}
	var took time.Duration
	// A pipeline's answers all arrive at its Sync, so a statement sharing one has no time of its own.
	if !head.start.IsZero() && !(head.typ == 'E' && executesBeforeSync(s.pending)) {
		took = time.Since(head.start)
	}
	if h := head.ran; h != nil && typ == 's' {
		// The next Execute of the portal goes on with the statement, keeping its caps and the rows counted so far.
		if i := slices.IndexFunc(s.pending, func(p sent) bool { return p.typ == 'E' && p.portal == head.portal && p.ran == nil }); i >= 0 {
			s.pending[i].resume(head)
		} else {
			if s.suspended == nil {
				s.suspended = map[string]sent{}
			}
			s.suspended[head.portal] = head
		}
	}
	// A suspended portal or an empty query ran nothing that says how its plan does, and nor does the Execute that goes on with one.
	if h := head.ran; h != nil && typ != 's' {
		if h.ran != nil && typ != 'I' && !head.resumed {
			h.ran(took, !head.failed && typ != 'E')
		}
		if h.returned != nil {
			h.returned(head.data[0], head.data[1])
		}
	}
	if head.sql != "" && s.record != nil {
		s.recordAnswer(head, typ, took)
	}
	if typ == 'E' && head.typ != 'Q' && head.typ != 'F' && head.typ != 'S' {
		// After an extended-protocol error Postgres ignores everything up to the next Sync.
		if i := slices.IndexFunc(s.pending, func(p sent) bool { return p.typ == 'S' }); i >= 0 {
			s.pending = s.pending[i:]
		} else {
			s.pending = s.pending[:0]
			s.skipping = true
		}
	}
	if head.typ == 'Q' || head.typ == 'E' {
		// Each statement of a pipeline gets its whole timeout from when the one before it ends.
		var next time.Duration
		if i := slices.IndexFunc(s.pending, func(p sent) bool { return p.typ == 'Q' || p.typ == 'E' }); i >= 0 {
			next = s.pending[i].timeout
		}
		s.timeStatement(next)
	}
	return head.how
}

// returnedRow counts a row of n bytes answering p, and cancels p's statement once it is past a cap; the caller holds mu.
func (s *session) returnedRow(p *sent, n int) {
	p.data[0]++
	p.data[1] += int64(n)
	h := p.ran
	if h == nil || !p.capped || s.cancel == nil || s.interrupted != nil {
		return
	}
	var i Interruption
	switch {
	case h.maxRows > 0 && p.data[0] > h.maxRows:
		i = Interruption{Code: "54000", Message: fmt.Sprintf("queryguard: canceling statement that returned more than %d rows", h.maxRows)}
	case h.maxBytes > 0 && p.data[1] > h.maxBytes:
		i = Interruption{Code: "54000", Message: fmt.Sprintf("queryguard: canceling statement that returned more than %d bytes", h.maxBytes)}
	default:
		return
	}
	i.Hint = "Add a LIMIT, or page through the rows."
	p.capped = false
	s.interrupted, s.interruptedRan = &i, p.ran
	s.cancelServer()
}

// cancelServer cancels the running statement from a goroutine, so the connection it opens holds up only the client's next message; the caller holds mu.
func (s *session) cancelServer() {
	done := make(chan struct{})
	s.cancelling = done
	go func() {
		defer safe.Recover(s.stop)
		defer s.endCancel(done)
		s.cancel()
	}()
}

// endCancel notes that the cancel cancelServer sent has reached Postgres.
func (s *session) endCancel(done chan struct{}) {
	s.mu.Lock()
	if s.cancelling == done {
		s.cancelling = nil
	}
	s.mu.Unlock()
	close(done)
}

// awaitCancel waits for the proxy's cancel in flight, if any, which would otherwise land on a statement sent before it does.
func (s *session) awaitCancel() {
	s.mu.Lock()
	done := s.cancelling
	s.mu.Unlock()
	if done != nil {
		<-done
	}
}

// recordAnswer records the statement head belongs to, now answered by a message of type typ; the caller holds mu.
func (s *session) recordAnswer(head sent, typ byte, took time.Duration) {
	f := Finished{SQL: head.sql, Took: took, Rows: head.reply.rows, Code: head.reply.code, Message: head.reply.message, Rejected: head.rejected}
	switch head.typ {
	case 'Q', 'E':
		// A suspended portal runs on at the next Execute, and an empty query runs nothing.
		if typ == 's' || typ == 'I' {
			return
		}
		if head.notRun {
			f.Took, f.NotRun = 0, true
		}
	case 'P', 'B':
		if typ != 'E' {
			return
		}
		f.Took, f.NotRun = 0, true
	default:
		return
	}
	s.record(f)
}

// readReply reads the rows of a CommandComplete or the code and text of an ErrorResponse.
func readReply(typ byte, body []byte) reply {
	var r reply
	if typ == 'C' {
		tag, _, _ := bytes.Cut(body, []byte{0})
		r.rows = rowsOf(string(tag))
		return r
	}
	for len(body) > 1 {
		field := body[0]
		value, rest, ok := bytes.Cut(body[1:], []byte{0})
		if !ok {
			break
		}
		switch field {
		case 'C':
			r.code = string(value)
		case 'M':
			r.message = string(value)
		}
		body = rest
	}
	return r
}

// rowsOf returns the rows a command tag such as "INSERT 0 3" or "SELECT 5" counts; 0 for a command that counts none.
func rowsOf(tag string) int64 {
	verb, _, _ := strings.Cut(tag, " ")
	switch verb {
	case "SELECT", "INSERT", "UPDATE", "DELETE", "MERGE", "FETCH", "MOVE", "COPY":
		_, count, _ := strings.CutLast(tag, " ")
		n, _ := strconv.ParseInt(count, 10, 64)
		return n
	}
	return 0
}

// executesBeforeSync reports whether pending holds a statement to run before its next Sync.
func executesBeforeSync(pending []sent) bool {
	for _, p := range pending {
		switch p.typ {
		case 'S':
			return false
		case 'Q', 'E':
			return true
		}
	}
	return false
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
	if size > maxMessageLen {
		return 0, 0, fmt.Errorf("message %q has length %d, above Postgres's limit of %d", head[0], size, maxMessageLen)
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
