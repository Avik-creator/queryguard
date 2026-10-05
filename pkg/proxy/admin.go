package proxy

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Avik-creator/queryguard/internal/safe"
	"github.com/Avik-creator/queryguard/pkg/policy"
	"github.com/Avik-creator/queryguard/pkg/wire"
	"github.com/jackc/pgx/v5/pgproto3"
)

// DefaultAdminAuthDatabase is the database a console login is checked against when AdminAuthDatabase is empty.
const DefaultAdminAuthDatabase = "postgres"

// defaultKill is how long KILL blocks a tenant or statement without FOR.
const defaultKill = time.Hour

// statsShown is how many rows SHOW STATS gives without a number.
const statsShown = 20

// admin serves the admin console once Postgres has checked the login against a real database, for a superuser or an admin role.
func (s *Server) admin(ctx context.Context, log *slog.Logger, client net.Conn, startup *pgproto3.StartupMessage, role string,
	key throttleKey, throttle policy.LoginThrottle) {
	auth := &pgproto3.StartupMessage{ProtocolVersion: startup.ProtocolVersion, Parameters: maps.Clone(startup.Parameters)}
	auth.Parameters["database"] = cmp.Or(s.AdminAuthDatabase, DefaultAdminAuthDatabase)
	actx, connected := context.WithTimeout(ctx, cmp.Or(s.StartupTimeout, DefaultStartupTimeout))
	server, err := s.Upstream.Acquire(actx, auth)
	connected()
	if err != nil {
		log.Error("connect to upstream", "client", client.RemoteAddr(), "err", err)
		wire.SendFatal(client, "08006", "queryguard: cannot connect to the database server")
		return
	}
	superuser := false
	// The console reads the client only after the login, so until then the client's password goes on to Postgres from here.
	clientIn := bufio.NewReader(client)
	replied := make(chan struct{})
	go func() {
		defer close(replied)
		defer safe.Recover(func(err error) { log.Error("relay the admin login", "err", err) })
		wire.RelayAuthReplies(clientIn, server)
	}()
	err = wire.RelayStartup(client, server, wire.StartupOptions{
		ChannelBinding: sameCertificate(client, server, s.TLSConfig),
		Report: func(name, value string) {
			if name == "is_superuser" {
				superuser = value == "on"
			}
		},
	})
	client.SetReadDeadline(time.Now())
	<-replied
	client.SetReadDeadline(time.Time{})
	// The console answers everything itself, so the server connection was only for the login.
	s.Upstream.Release(server)
	if e, ok := errors.AsType[*wire.LoginRefusedError](err); ok && (e.Code == "28P01" || e.Code == "28000") && throttle.Failures > 0 {
		s.throttle.failed(key, time.Now(), throttle)
	}
	if err != nil {
		return
	}
	s.throttle.succeeded(key)
	if p := s.ActivePolicy(); !superuser && (p == nil || !p.Admin(role)) {
		log.Warn("refused the admin console to a role that is neither a superuser nor an admin role", "client", client.RemoteAddr(), "role", role)
		wire.SendFatal(client, "42501", "queryguard: only superusers and admin_roles may use the admin console")
		return
	}
	log.Info("admin console login", "client", client.RemoteAddr(), "role", role)
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()

	backend := pgproto3.NewBackend(clientIn, client)
	failed := false // an extended-protocol message was refused, so the rest up to Sync are skipped
	for {
		msg, err := backend.Receive()
		if err != nil {
			return
		}
		switch m := msg.(type) {
		case *pgproto3.Query:
			res, err := s.adminCommand(m.String, role, log)
			if err != nil {
				backend.Send(&pgproto3.ErrorResponse{Severity: "ERROR", SeverityUnlocalized: "ERROR", Code: adminCode(err), Message: err.Error()})
			} else {
				res.send(backend)
			}
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		case *pgproto3.Parse, *pgproto3.Bind, *pgproto3.Describe, *pgproto3.Execute, *pgproto3.Close:
			if !failed {
				failed = true
				backend.Send(&pgproto3.ErrorResponse{Severity: "ERROR", SeverityUnlocalized: "ERROR", Code: "0A000",
					Message: "queryguard: the admin console takes simple queries only", Hint: "Use psql, or a driver's simple protocol."})
			}
		case *pgproto3.Sync:
			failed = false
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		case *pgproto3.Terminate:
			return
		}
		if err := backend.Flush(); err != nil {
			return
		}
	}
}

// adminError is a console error with its SQLSTATE.
type adminError struct{ code, msg string }

func (e *adminError) Error() string { return e.msg }

func adminCode(err error) string {
	if e, ok := errors.AsType[*adminError](err); ok {
		return e.code
	}
	return "XX000"
}

// syntaxError is the error for a command the console doesn't know.
func syntaxError(format string, args ...any) error {
	return &adminError{"42601", "queryguard: " + fmt.Sprintf(format, args...) + "; SHOW HELP lists the commands"}
}

// result is a command's answer: rows of text under columns, or only a tag.
type result struct {
	columns []string
	rows    [][]string
	tag     string
}

func (r result) send(b *pgproto3.Backend) {
	if r.columns != nil {
		fields := make([]pgproto3.FieldDescription, len(r.columns))
		for i, c := range r.columns {
			// Every value is text (type 25), so psql shows it as it is.
			fields[i] = pgproto3.FieldDescription{Name: []byte(c), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1}
		}
		b.Send(&pgproto3.RowDescription{Fields: fields})
		for _, row := range r.rows {
			values := make([][]byte, len(row))
			for i, v := range row {
				values[i] = []byte(v)
			}
			b.Send(&pgproto3.DataRow{Values: values})
		}
	}
	b.Send(&pgproto3.CommandComplete{CommandTag: []byte(r.tag)})
}

// adminHelp lists the console's commands.
var adminHelp = [][]string{
	{"SHOW TENANTS", "each tenant's budget left, rate, recent use and running statements"},
	{"SHOW STATS [n]", "the n statements with the most total time (20)"},
	{"SHOW ANOMALIES", "anomalies lately started and ended"},
	{"SHOW FLIPS", "plan flips lately seen"},
	{"SHOW WATCH", "the runaway watch list"},
	{"SHOW KILLS", "tenants and statements blocked by KILL"},
	{"SHOW ALLOWLIST", "each role's learned statements"},
	{"KILL TENANT name [FOR duration]", "block a tenant's statements, for an hour unless FOR says"},
	{"KILL STATEMENT fingerprint [FOR duration]", "block a statement, by the fingerprint SHOW STATS gives"},
	{"UNKILL TENANT name | UNKILL STATEMENT fingerprint", "lift a kill"},
	{"UNWATCH database fingerprint", "take a statement off the runaway watch list"},
	{"RELOAD", "read the config file again, as SIGHUP does"},
}

// adminCommand runs one console command.
func (s *Server) adminCommand(sql, role string, log *slog.Logger) (result, error) {
	words := adminWords(sql)
	if len(words) == 0 {
		return result{tag: "EMPTY"}, nil
	}
	verb := strings.ToLower(words[0])
	arg := func(i int) string {
		if i < len(words) {
			return words[i]
		}
		return ""
	}
	switch verb {
	case "help":
		return result{columns: []string{"command", "does"}, rows: adminHelp, tag: "SHOW"}, nil
	case "show":
		return s.adminShow(strings.ToLower(arg(1)), words[min(2, len(words)):])
	case "kill", "unkill":
		kind, name := policy.KillKind(strings.ToLower(arg(1))), arg(2)
		if kind == "statement" {
			kind = policy.KillFingerprint
		}
		if (kind != policy.KillTenant && kind != policy.KillFingerprint) || name == "" {
			return result{}, syntaxError("%s takes TENANT name or STATEMENT fingerprint", strings.ToUpper(verb))
		}
		if verb == "unkill" {
			if !s.Kills.Unkill(kind, name) {
				return result{}, &adminError{"42704", fmt.Sprintf("queryguard: no kill of %s %s", kind, name)}
			}
			log.Info("kill lifted", "by", role, "kind", kind, "name", name)
			return result{tag: "UNKILL"}, nil
		}
		d := defaultKill
		if strings.EqualFold(arg(3), "for") {
			var err error
			if d, err = time.ParseDuration(arg(4)); err != nil || d <= 0 {
				return result{}, syntaxError("FOR takes a duration such as '10m'")
			}
		}
		s.Kills.Kill(kind, name, time.Now().Add(d))
		log.Warn("kill switch on", "by", role, "kind", kind, "name", name, "for", d)
		return result{tag: "KILL"}, nil
	case "unwatch":
		if arg(2) == "" {
			return result{}, syntaxError("UNWATCH takes a database and a fingerprint")
		}
		if !s.Runaways.Remove(arg(1), arg(2)) {
			return result{}, &adminError{"42704", "queryguard: that statement is not watched"}
		}
		return result{tag: "UNWATCH"}, nil
	case "reload":
		if s.Reload == nil {
			return result{}, &adminError{"55000", "queryguard: there is no config file to reload"}
		}
		if err := s.Reload(); err != nil {
			return result{}, &adminError{"F0000", "queryguard: config not reloaded: " + err.Error()}
		}
		log.Info("config reloaded from the admin console", "by", role)
		return result{tag: "RELOAD"}, nil
	}
	return result{}, syntaxError("unknown command %q", words[0])
}

// adminShow answers SHOW what.
func (s *Server) adminShow(what string, rest []string) (result, error) {
	now := time.Now()
	switch what {
	case "help":
		return result{columns: []string{"command", "does"}, rows: adminHelp, tag: "SHOW"}, nil
	case "tenants":
		r := result{columns: []string{"tenant", "budget_left", "rate", "usage", "running"}, tag: "SHOW"}
		if sc := s.scheduler(); sc != nil {
			for _, t := range sc.Tenants() {
				r.rows = append(r.rows, []string{t.Name, num(t.Tokens), num(t.Rate), num(t.Usage), strconv.Itoa(t.Running)})
			}
		}
		return r, nil
	case "stats":
		if s.Stats == nil {
			return result{}, &adminError{"55000", "queryguard: query stats are off"}
		}
		n := statsShown
		if len(rest) > 0 {
			var err error
			if n, err = strconv.Atoi(rest[0]); err != nil || n <= 0 {
				return result{}, syntaxError("SHOW STATS takes a number of rows")
			}
		}
		r := result{columns: []string{"database", "role", "tenant", "fingerprint", "calls", "rows", "total_ms", "p50_ms", "p95_ms", "p99_ms",
			"errors", "rejections", "shared_hit", "shared_read", "temp_written", "wal_bytes", "query"}, tag: "SHOW"}
		for _, row := range s.Stats.Rows()[:min(n, len(s.Stats.Rows()))] {
			r.rows = append(r.rows, []string{row.Database, row.Role, row.Tenant, row.Fingerprint, itoa(row.Calls), itoa(row.Rows), ms(row.Total),
				ms(row.P50), ms(row.P95), ms(row.P99), codes(row.Errors), codes(row.Rejections), itoa(row.Buffers.SharedHit),
				itoa(row.Buffers.SharedRead), itoa(row.Buffers.TempWritten), num(row.Buffers.WALBytes), row.Query})
		}
		return r, nil
	case "anomalies":
		r := result{columns: []string{"at", "signal", "state", "value", "baseline", "statements", "flips", "lock_waits"}, tag: "SHOW"}
		if s.Stats != nil {
			for _, a := range s.Stats.Anomalies() {
				state := "started"
				if a.Ended {
					state = "ended"
				}
				r.rows = append(r.rows, []string{a.At.Format(time.RFC3339), a.Signal, state, num(a.Value), num(a.Baseline),
					strings.Join(a.Statements, "; "), strings.Join(a.Flips, "; "), strconv.Itoa(a.LockWaits)})
			}
		}
		return r, nil
	case "flips":
		r := result{columns: []string{"at", "database", "fingerprint", "query"}, tag: "SHOW"}
		if s.Stats != nil {
			for _, f := range s.Stats.Flips() {
				r.rows = append(r.rows, []string{f.At.Format(time.RFC3339), f.Database, f.Fingerprint, f.Query})
			}
		}
		return r, nil
	case "watch":
		r := result{columns: []string{"database", "fingerprint", "reason", "until", "query"}, tag: "SHOW"}
		for _, w := range s.Runaways.List(now) {
			r.rows = append(r.rows, []string{w.Database, w.Fingerprint, w.Reason, w.Until.Format(time.RFC3339), w.Query})
		}
		return r, nil
	case "kills":
		r := result{columns: []string{"kind", "name", "until"}, tag: "SHOW"}
		for _, k := range s.Kills.List(now) {
			kind := string(k.Kind)
			if k.Kind == policy.KillFingerprint {
				kind = "statement"
			}
			r.rows = append(r.rows, []string{kind, k.Name, k.Until.Format(time.RFC3339)})
		}
		return r, nil
	case "allowlist":
		r := result{columns: []string{"role", "fingerprint", "query"}, tag: "SHOW"}
		for _, e := range s.Allowlist.List() {
			r.rows = append(r.rows, []string{e.Role, e.Fingerprint, e.Query})
		}
		return r, nil
	}
	return result{}, syntaxError("SHOW what? %q", what)
}

// adminWords splits a command into words, a single-quoted word whole and unquoted, dropping a trailing semicolon.
func adminWords(sql string) []string {
	sql = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(sql), ";"))
	var words []string
	for sql != "" {
		sql = strings.TrimLeft(sql, " \t\r\n")
		if sql == "" {
			break
		}
		if sql[0] == '\'' {
			word, rest, _ := strings.Cut(sql[1:], "'")
			words, sql = append(words, word), rest
			continue
		}
		end := strings.IndexAny(sql, " \t\r\n")
		if end < 0 {
			end = len(sql)
		}
		words, sql = append(words, sql[:end]), sql[end:]
	}
	return words
}

func num(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }
func itoa(n int64) string  { return strconv.FormatInt(n, 10) }
func ms(d time.Duration) string {
	return strconv.FormatFloat(float64(d)/float64(time.Millisecond), 'f', 3, 64)
}

// codes writes counts by SQLSTATE as code:n, code:n.
func codes(m map[string]int64) string {
	var parts []string
	for _, code := range slices.Sorted(maps.Keys(m)) {
		parts = append(parts, code+":"+itoa(m[code]))
	}
	return strings.Join(parts, ", ")
}
