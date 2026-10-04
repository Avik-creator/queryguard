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

	"github.com/jackc/pgx/v5/pgproto3"
)

// maxCheckedLen caps the Query and Parse messages read whole for checking; longer ones go to CheckTooLong.
const maxCheckedLen = 16 << 20

// bufSize matches Postgres's own 8 KB send buffer.
const bufSize = 8 << 10

// Checker decides whether a statement may run.
type Checker interface {
	// Check returns the error to send instead of running sql, or nil to run it; set says how Postgres will read sql.
	Check(sql string, set Settings) *pgproto3.ErrorResponse
	// CheckTooLong decides on a statement of size bytes, too long to read whole.
	CheckTooLong(size int) *pgproto3.ErrorResponse
}

// Settings are the server settings that change how Postgres reads statement text; an empty field is unknown.
type Settings struct {
	StandardConformingStrings string // "off" makes a backslash in '…' an escape
	ClientEncoding            string // Postgres converts statements from it before parsing them
}

// Relay runs login, which passes each ParameterStatus to report, then relays messages both ways until either side
// closes; it closes both and returns the first error.
func Relay(client, server net.Conn, check Checker, login func(client io.Writer, server io.Reader, report func(name, value string)) error) error {
	s := &session{
		check:     check,
		clientIn:  bufio.NewReaderSize(client, bufSize),
		clientOut: bufio.NewWriterSize(client, bufSize),
		serverIn:  bufio.NewReaderSize(server, bufSize),
		serverOut: bufio.NewWriterSize(server, bufSize),
		ready:     make(chan struct{}),
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
	check     Checker
	ready     chan struct{} // closed once login has ended
	clientIn  *bufio.Reader
	serverIn  *bufio.Reader
	serverOut *bufio.Writer // only fromClient writes to the server

	mu        sync.Mutex
	clientOut *bufio.Writer // both loops write to the client, so only under mu
	status    byte          // transaction status from the last ReadyForQuery; 0 until login ends
	pending   []sent        // messages the server has yet to finish answering, oldest first
	skipping  bool          // the server ignores everything up to the next Sync after an extended-protocol error
	reported  Settings      // as last reported by the server

	// Only fromClient uses these.
	inBatch bool      // extended-protocol messages went to the server since the last Sync
	discard untilSync // what to do with client messages after a rejected Parse
}

// sent is a client message the server will answer; the server's answers to a hidden one, except errors, don't reach the client.
type sent struct {
	typ    byte
	hidden bool
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
		if rej := s.check.Check(sql, s.settings()); rej != nil {
			return s.reject(typ, rej)
		}
	}
	s.track(typ, false)
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

// forward streams one client message to the server.
func (s *session) forward(typ byte, n int) error {
	s.track(typ, false)
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
		s.track('Q', false)
		return writeMessages(s.serverOut, &pgproto3.Query{String: do})
	}
	s.discard = forwardSync
	for _, t := range []byte{'P', 'B', 'E'} {
		s.track(t, true)
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

// track records a client message on its way to the server.
func (s *session) track(typ byte, hidden bool) {
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
	s.pending = append(s.pending, sent{typ: typ, hidden: hidden})
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

// relayAnswer passes one server message to the client, holding mu so a rejection can't land between it and its effect on pending.
func (s *session) relayAnswer(typ byte, n int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	if s.answered(typ) {
		_, err := s.serverIn.Discard(n)
		return unexpected(err)
	}
	writeHeader(s.clientOut, typ, n)
	return copyBody(s.clientOut, s.serverIn, n)
}

// answered matches a server message to the oldest pending client message and reports whether to hide it.
func (s *session) answered(typ byte) (hide bool) {
	// Notices, parameter changes and notifications can arrive at any time.
	if len(s.pending) == 0 || typ == 'N' || typ == 'S' || typ == 'A' {
		return false
	}
	head := s.pending[0]
	hide = head.hidden && typ != 'E'
	if !finishes(head.typ, typ) {
		return hide
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
	return hide
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
