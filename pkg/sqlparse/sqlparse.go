// Package sqlparse reads SQL with the Postgres parser and reports what the rules need to know.
package sqlparse

import (
	"maps"
	"net/url"
	"slices"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Query is what the rules need to know about one query string, gathered from every statement in it.
type Query struct {
	DDL                 bool     // a statement Postgres logs as DDL under log_statement = 'ddl'
	Opaque              bool     // a DO block or CALL, whose body can run anything
	ChangesEveryRow     bool     // UPDATE or DELETE without WHERE, or TRUNCATE
	BlockingIndexChange bool     // CREATE INDEX, DROP INDEX or REINDEX without CONCURRENTLY, which blocks writes
	Schemas             []string // schemas named explicitly, sorted, without duplicates
	UnknownSearchPath   bool     // set_config('search_path', …) with a value known only when it runs
	Explainable         bool     // Plan is set
	Plan                string   // the one statement whose plan is the query's: SELECT, INSERT, UPDATE, DELETE, MERGE, DECLARE, CREATE TABLE AS or EXECUTE, alone or among transaction control, or the query EXPLAIN ANALYZE or COPY TO runs
	Unplanned           bool     // it does work that no one plan covers, as several statements doing some do
	Analyzes            bool     // VACUUM or ANALYZE, which refresh the planner's statistics
	Cursor              bool     // DECLARE, whose query runs in the FETCHes that follow
	TransactionControl  bool     // only BEGIN, COMMIT, ROLLBACK, SAVEPOINT and the like, which do no work of their own
	ChangesTimeout      bool     // may change statement_timeout: SET or RESET of it, or set_config of it or of a name known only when it runs
	ChangesRole         bool     // may change the role statements run as: SET ROLE, SET SESSION AUTHORIZATION, or set_config of them or of an unknown name
	Functions           []string // functions called by name, as schema.name when qualified, sorted, without duplicates
	ReadOnly            bool     // only SELECTs or VALUES, without INTO, FOR UPDATE and the like, or a CTE that changes rows
	Named               bool     // a single FETCH, MOVE or EXECUTE, which runs a cursor or prepared statement its text only names
	// Writes is anything but reading: DML, DDL, row locks, COPY FROM or to a file, a READ WRITE transaction, changing the read-only
	// settings or the role, nextval, setval, set_config, and any statement not known to only read, such as NOTIFY or VACUUM.
	Writes bool
}

// writingFunctions change state although a SELECT may call them, which a read-only transaction refuses too.
var writingFunctions = []string{"nextval", "setval", "set_config", "pg_notify"}

// readOnlySettings turn a session's or transaction's read-only mode off when set or reset.
var readOnlySettings = []string{"default_transaction_read_only", "transaction_read_only"}

// notDDL lists the statement types Postgres's GetCommandLogLevel does not log as DDL; every other *Stmt is DDL.
var notDDL = map[protoreflect.Name]bool{
	"RawStmt": true, "SelectStmt": true, "InsertStmt": true, "UpdateStmt": true, "DeleteStmt": true,
	"MergeStmt": true, "TruncateStmt": true, "CopyStmt": true, "TransactionStmt": true,
	"DeclareCursorStmt": true, "ClosePortalStmt": true, "FetchStmt": true, "PrepareStmt": true,
	"ExecuteStmt": true, "DeallocateStmt": true, "DoStmt": true, "NotifyStmt": true, "ListenStmt": true,
	"UnlistenStmt": true, "LoadStmt": true, "CallStmt": true, "VacuumStmt": true, "ExplainStmt": true,
	"VariableSetStmt": true, "VariableShowStmt": true, "DiscardStmt": true, "LockStmt": true,
	"ConstraintsSetStmt": true, "CheckPointStmt": true, "ReindexStmt": true, "PLAssignStmt": true,
	"ReturnStmt": true,
	// These never stand alone in a raw parse tree: the first comes from analysis, the second sits inside ALTER TABLE.
	"SetOperationStmt": true, "ReplicaIdentityStmt": true,
}

// namesTableFirst are the object types whose DROP names a table and then the object on it.
var namesTableFirst = []pg_query.ObjectType{pg_query.ObjectType_OBJECT_TRIGGER, pg_query.ObjectType_OBJECT_RULE, pg_query.ObjectType_OBJECT_POLICY}

// Analyze parses sql, which may hold several statements, and walks every node, so nested statements count too.
func Analyze(sql string) (Query, error) {
	tree, err := pg_query.Parse(sql)
	if err != nil {
		return Query{}, err
	}
	var q Query
	q.Plan, q.Unplanned = planOf(sql, tree)
	q.Explainable = q.Plan != ""
	if len(tree.Stmts) == 1 {
		_, q.Cursor = tree.Stmts[0].GetStmt().GetNode().(*pg_query.Node_DeclareCursorStmt)
		switch tree.Stmts[0].GetStmt().GetNode().(type) {
		case *pg_query.Node_FetchStmt, *pg_query.Node_ExecuteStmt:
			q.Named = true
		}
	}
	q.TransactionControl = len(tree.Stmts) > 0 && !slices.ContainsFunc(tree.Stmts, func(s *pg_query.RawStmt) bool {
		_, ok := s.GetStmt().GetNode().(*pg_query.Node_TransactionStmt)
		return !ok
	})
	schemas, functions := map[string]bool{}, map[string]bool{}
	writes := false
	add := func(schema string) {
		if schema != "" {
			schemas[schema] = true
		}
	}
	for _, st := range tree.Stmts {
		switch st.GetStmt().GetNode().(type) {
		case *pg_query.Node_SelectStmt, *pg_query.Node_VariableShowStmt, *pg_query.Node_ExplainStmt, *pg_query.Node_TransactionStmt,
			*pg_query.Node_VariableSetStmt, *pg_query.Node_DeclareCursorStmt, *pg_query.Node_FetchStmt, *pg_query.Node_ClosePortalStmt,
			*pg_query.Node_PrepareStmt, *pg_query.Node_ExecuteStmt, *pg_query.Node_DeallocateStmt, *pg_query.Node_DiscardStmt,
			*pg_query.Node_CopyStmt:
		default:
			q.Writes = true
		}
	}
	walk(tree.ProtoReflect(), func(m protoreflect.Message) {
		if name := m.Descriptor().Name(); strings.HasSuffix(string(name), "Stmt") && !notDDL[name] {
			q.DDL = true
		}
		switch n := m.Interface().(type) {
		case *pg_query.InsertStmt, *pg_query.MergeStmt, *pg_query.LockingClause:
			writes = true
		case *pg_query.SelectStmt:
			// SELECT INTO creates a table.
			q.DDL = q.DDL || n.IntoClause != nil
			writes = writes || n.IntoClause != nil
		case *pg_query.UpdateStmt:
			writes = true
			q.ChangesEveryRow = q.ChangesEveryRow || n.WhereClause == nil
			// Updating the pg_settings view calls set_config for each row, with names and values known only when it runs.
			if r := n.GetRelation(); r.GetRelname() == "pg_settings" && (r.GetSchemaname() == "" || r.GetSchemaname() == "pg_catalog") {
				q.UnknownSearchPath, q.ChangesTimeout, q.ChangesRole = true, true, true
			}
		case *pg_query.DeleteStmt:
			writes = true
			q.ChangesEveryRow = q.ChangesEveryRow || n.WhereClause == nil
		case *pg_query.TruncateStmt:
			q.ChangesEveryRow = true
		case *pg_query.DiscardStmt:
			// DISCARD ALL runs RESET ALL and SET SESSION AUTHORIZATION DEFAULT.
			if n.Target == pg_query.DiscardMode_DISCARD_ALL {
				writes, q.ChangesRole, q.ChangesTimeout = true, true, true
			}
		case *pg_query.IndexStmt:
			// ON ONLY (inh false) builds nothing; it starts indexing a partitioned table, which CONCURRENTLY can't do.
			q.BlockingIndexChange = q.BlockingIndexChange || (!n.Concurrent && n.GetRelation().GetInh())
		case *pg_query.ReindexStmt:
			q.BlockingIndexChange = q.BlockingIndexChange || !concurrently(n.Params)
		case *pg_query.DropStmt:
			q.BlockingIndexChange = q.BlockingIndexChange || (n.RemoveType == pg_query.ObjectType_OBJECT_INDEX && !n.Concurrent)
			for _, obj := range n.Objects {
				switch {
				case n.RemoveType == pg_query.ObjectType_OBJECT_SCHEMA:
					add(obj.GetString_().GetSval())
				case slices.Contains(namesTableFirst, n.RemoveType):
					if names := obj.GetList().GetItems(); len(names) > 0 {
						add(schemaOf(names[:len(names)-1]))
					}
				default:
					add(schemaOf(obj.GetList().GetItems()))
				}
			}
		case *pg_query.DoStmt, *pg_query.CallStmt:
			q.Opaque = true
		case *pg_query.TransactionStmt:
			switch n.Kind {
			case pg_query.TransactionStmtKind_TRANS_STMT_PREPARE, pg_query.TransactionStmtKind_TRANS_STMT_COMMIT_PREPARED,
				pg_query.TransactionStmtKind_TRANS_STMT_ROLLBACK_PREPARED:
				q.Writes = true
			}
		case *pg_query.DefElem:
			// READ WRITE in BEGIN, SET TRANSACTION and SET SESSION CHARACTERISTICS is transaction_read_only = 0.
			if n.Defname == "transaction_read_only" && n.GetArg().GetAConst().GetIval().GetIval() == 0 {
				q.Writes = true
			}
		case *pg_query.CopyStmt:
			q.Writes = q.Writes || n.IsFrom || n.IsProgram || n.Filename != ""
		case *pg_query.VacuumStmt:
			q.Analyzes = true
		case *pg_query.RangeVar:
			add(n.Schemaname)
		case *pg_query.FuncCall:
			add(schemaOf(n.Funcname))
			functions[funcName(n.Funcname)] = true
			q.Writes = q.Writes || slices.ContainsFunc(writingFunctions, func(f string) bool {
				return strings.EqualFold(f, n.Funcname[len(n.Funcname)-1].GetString_().GetSval())
			})
			if setting, ok := settingSet(n); ok {
				q.ChangesTimeout = q.ChangesTimeout || setting == nil || strings.EqualFold(*setting, statementTimeout)
				q.ChangesRole = q.ChangesRole || setting == nil || roleSetting(*setting)
			}
			if path, ok := searchPathSet(n); ok {
				q.UnknownSearchPath = q.UnknownSearchPath || path == nil
				for _, s := range path {
					add(s)
				}
			}
		case *pg_query.TypeName:
			// The parser itself writes built-in types such as int as pg_catalog.int4.
			if schema := schemaOf(n.Names); schema != "pg_catalog" {
				add(schema)
			}
		case *pg_query.ObjectWithArgs:
			add(schemaOf(n.Objname))
		case *pg_query.CreateSchemaStmt:
			add(n.Schemaname)
		case *pg_query.AlterObjectSchemaStmt:
			add(n.Newschema)
		case *pg_query.GrantStmt:
			if n.Targtype == pg_query.GrantTargetType_ACL_TARGET_ALL_IN_SCHEMA {
				for _, obj := range n.Objects {
					add(obj.GetString_().GetSval())
				}
			}
		case *pg_query.VariableSetStmt:
			q.ChangesTimeout = q.ChangesTimeout || strings.EqualFold(n.Name, statementTimeout)
			q.ChangesRole = q.ChangesRole || roleSetting(n.Name)
			q.Writes = q.Writes || roleSetting(n.Name) || n.Kind == pg_query.VariableSetKind_VAR_RESET_ALL ||
				slices.ContainsFunc(readOnlySettings, func(r string) bool { return strings.EqualFold(r, n.Name) })
			if strings.EqualFold(n.Name, searchPath) {
				for _, arg := range n.Args {
					// "$user" stands for the role's own schema, which Postgres skips when it doesn't exist.
					if s := arg.GetAConst().GetSval().GetSval(); !strings.HasPrefix(s, "$") {
						add(s)
					}
				}
			}
		}
	})
	q.Writes = q.Writes || writes || q.DDL || q.Opaque
	q.Schemas = slices.Sorted(maps.Keys(schemas))
	q.ReadOnly = !writes && len(tree.Stmts) > 0 && !slices.ContainsFunc(tree.Stmts, func(s *pg_query.RawStmt) bool {
		_, ok := s.GetStmt().GetNode().(*pg_query.Node_SelectStmt)
		return !ok
	})
	if len(functions) > 0 {
		q.Functions = slices.Sorted(maps.Keys(functions))
	}
	return q, nil
}

// funcName joins a function's qualified name of String nodes with dots.
func funcName(names []*pg_query.Node) string {
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = n.GetString_().GetSval()
	}
	return strings.Join(parts, ".")
}

// schemaOf returns the schema in a qualified name of String nodes ([catalog.]schema.name), or "" for a bare name.
func schemaOf(names []*pg_query.Node) string {
	if len(names) < 2 {
		return ""
	}
	return names[len(names)-2].GetString_().GetSval()
}

// searchPath is the setting schema_allowlist watches; Postgres matches setting names ignoring case.
const searchPath = "search_path"

// statementTimeout is the setting that cancels statements running longer than it.
const statementTimeout = "statement_timeout"

// roleSetting reports whether name is a setting that changes the role statements run as, and so what row-level security lets them see.
func roleSetting(name string) bool {
	return strings.EqualFold(name, "role") || strings.EqualFold(name, "session_authorization")
}

// settingSet returns the name of the setting a set_config call changes, nil when it is known only when it runs; ok is false
// for any other call.
func settingSet(call *pg_query.FuncCall) (setting *string, ok bool) {
	if call.Funcname[len(call.Funcname)-1].GetString_().GetSval() != "set_config" || len(call.Args) < 2 {
		return nil, false
	}
	if c := call.Args[0].GetAConst().GetSval(); c != nil {
		return &c.Sval, true
	}
	return nil, true
}

// searchPathSet reports whether call may be set_config('search_path', …) and returns the schemas it sets, or nil when the name or value is not a constant.
func searchPathSet(call *pg_query.FuncCall) (schemas []string, ok bool) {
	name := call.Funcname[len(call.Funcname)-1].GetString_().GetSval()
	if name != "set_config" || len(call.Args) < 2 {
		return nil, false
	}
	setting, value := call.Args[0].GetAConst().GetSval(), call.Args[1].GetAConst().GetSval()
	switch {
	case setting == nil:
		return nil, true
	case !strings.EqualFold(setting.Sval, searchPath):
		return nil, false
	case value == nil:
		return nil, true
	}
	return SearchPath(value.Sval), true
}

// SearchPath returns the schemas in a search_path value, folding unquoted names to lower case and skipping "$user".
func SearchPath(value string) []string {
	schemas := []string{}
	for part := range strings.SplitSeq(value, ",") {
		part = strings.TrimSpace(part)
		// Postgres folds unquoted names to lower case and keeps quoted ones as written.
		if unquoted, quoted := strings.CutPrefix(part, `"`); quoted {
			part = strings.ReplaceAll(strings.TrimSuffix(unquoted, `"`), `""`, `"`)
		} else {
			part = strings.ToLower(part)
		}
		if part != "" && !strings.HasPrefix(part, "$") {
			schemas = append(schemas, part)
		}
	}
	return schemas
}

// BackslashInString reports whether sql has a backslash inside a '…' string, which Postgres reads as an escape when
// standard_conforming_strings is off; Analyze reads it with the setting on. SQL that can't be scanned counts as having one.
func BackslashInString(sql string) bool {
	if !strings.Contains(sql, `\`) {
		return false
	}
	scan, err := pg_query.Scan(sql)
	if err != nil {
		return true
	}
	return slices.ContainsFunc(scan.Tokens, func(t *pg_query.ScanToken) bool {
		text := sql[t.Start:t.End]
		// Plain strings start with a quote; E'…' and $$…$$ strings are also SCONST but read backslashes the same either way.
		plain := t.Token == pg_query.Token_SCONST && strings.HasPrefix(text, "'") || t.Token == pg_query.Token_USCONST
		return plain && strings.Contains(text, `\`)
	})
}

// concurrently reports whether REINDEX options turn on CONCURRENTLY; an option without a value means on.
func concurrently(params []*pg_query.Node) bool {
	for _, p := range params {
		if d := p.GetDefElem(); d != nil && d.Defname == "concurrently" {
			c := d.GetArg().GetAConst()
			return d.Arg == nil || c.GetBoolval().GetBoolval() || c.GetIval().GetIval() != 0 ||
				slices.Contains([]string{"true", "on", "yes", "1"}, strings.ToLower(c.GetSval().GetSval()))
		}
	}
	return false
}

// walk calls visit on m and on every message below it.
// planOf returns the text of the one statement in tree, sql's, whose plan is sql's, and whether sql does work no one plan covers.
func planOf(sql string, tree *pg_query.ParseResult) (plan string, unplanned bool) {
	var plans []string
	others := false
	deparse := func(n *pg_query.Node) string {
		text, err := pg_query.Deparse(&pg_query.ParseResult{Version: tree.Version, Stmts: []*pg_query.RawStmt{{Stmt: n}}})
		if n == nil || err != nil {
			return ""
		}
		return text
	}
	stmts := tree.Stmts
	for _, st := range stmts {
		switch n := st.GetStmt().GetNode().(type) {
		case *pg_query.Node_SelectStmt, *pg_query.Node_InsertStmt, *pg_query.Node_UpdateStmt, *pg_query.Node_DeleteStmt,
			*pg_query.Node_MergeStmt, *pg_query.Node_DeclareCursorStmt, *pg_query.Node_CreateTableAsStmt, *pg_query.Node_ExecuteStmt:
			plans = append(plans, statementText(sql, st, len(stmts)))
		case *pg_query.Node_ExplainStmt:
			if analyzes(n.ExplainStmt) {
				plans = append(plans, deparse(n.ExplainStmt.GetQuery()))
			}
		case *pg_query.Node_CopyStmt:
			// COPY FROM costs what its data does, which no plan knows.
			if c := n.CopyStmt; !c.IsFrom && c.Query != nil {
				plans = append(plans, deparse(c.Query))
			} else if !c.IsFrom && c.Relation != nil {
				plans = append(plans, deparse(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: &pg_query.SelectStmt{
					TargetList: []*pg_query.Node{pg_query.MakeResTargetNodeWithVal(pg_query.MakeColumnRefNode([]*pg_query.Node{pg_query.MakeAStarNode()}, 0), 0)},
					FromClause: []*pg_query.Node{{Node: &pg_query.Node_RangeVar{RangeVar: c.Relation}}},
				}}}))
			}
		case *pg_query.Node_TransactionStmt:
		default:
			others = true
		}
	}
	// A statement before the planned one, such as SET search_path, could change its plan, and EXPLAIN plans only one.
	if len(plans) > 1 || (len(plans) == 1 && others) || slices.Contains(plans, "") {
		return "", true
	}
	if len(plans) == 1 {
		return plans[0], false
	}
	return "", false
}

// statementText returns st's own text in sql, which holds n statements.
func statementText(sql string, st *pg_query.RawStmt, n int) string {
	if n == 1 {
		return sql
	}
	start := int(st.StmtLocation)
	end := len(sql)
	if st.StmtLen > 0 {
		end = start + int(st.StmtLen)
	}
	return strings.TrimSpace(sql[start:end])
}

// analyzes reports whether an EXPLAIN runs its statement, as with ANALYZE.
func analyzes(e *pg_query.ExplainStmt) bool {
	for _, o := range e.GetOptions() {
		d := o.GetDefElem()
		if !strings.EqualFold(d.GetDefname(), "analyze") {
			continue
		}
		switch arg := d.GetArg(); {
		case arg == nil:
			return true
		case arg.GetBoolean() != nil:
			return arg.GetBoolean().GetBoolval()
		default:
			v := strings.ToLower(arg.GetString_().GetSval())
			return v != "" && (strings.HasPrefix("true", v) || strings.HasPrefix("yes", v) || v == "on" || v == "1")
		}
	}
	return false
}

func walk(m protoreflect.Message, visit func(protoreflect.Message)) {
	visit(m)
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.Message() == nil || fd.IsMap():
		case fd.IsList():
			for i := range v.List().Len() {
				walk(v.List().Get(i).Message(), visit)
			}
		default:
			walk(v.Message(), visit)
		}
		return true
	})
}

// Fingerprint identifies sql's shape, ignoring constants, as 16 hex digits; it is empty when sql doesn't parse.
func Fingerprint(sql string) string {
	fp, _ := pg_query.Fingerprint(sql)
	return fp
}

// Normalize replaces sql's constants with $1, $2…, so it can be logged without the values; it is empty when sql doesn't parse.
func Normalize(sql string) string {
	n, _ := pg_query.Normalize(sql)
	return n
}

var _ proto.Message = (*pg_query.ParseResult)(nil)

// Tags returns the sqlcommenter key-value pairs in sql's last /* */ comment, or nil when that comment holds none.
func Tags(sql string) map[string]string {
	if !strings.Contains(sql, "/*") {
		return nil
	}
	scan, err := pg_query.Scan(sql)
	if err != nil {
		return nil
	}
	var comment string
	for _, t := range slices.Backward(scan.Tokens) {
		if t.Token == pg_query.Token_C_COMMENT {
			comment = sql[t.Start:t.End]
			break
		}
	}
	body := strings.TrimSuffix(strings.TrimPrefix(comment, "/*"), "*/")
	tags := map[string]string{}
	// Pairs are key='value', comma-separated; both parts are URL-encoded, and a quote in a value is escaped as \'.
	for rest := strings.TrimSpace(body); rest != ""; {
		key, after, ok := strings.Cut(rest, "='")
		end := -1
		for i := 0; ok && i < len(after) && end < 0; i++ {
			switch after[i] {
			case '\\':
				i++
			case '\'':
				end = i
			}
		}
		if end < 0 {
			return nil
		}
		k, kerr := url.PathUnescape(strings.ReplaceAll(strings.TrimSpace(key), `\'`, "'"))
		v, verr := url.PathUnescape(strings.ReplaceAll(after[:end], `\'`, "'"))
		if kerr != nil || verr != nil {
			return nil
		}
		tags[k] = v
		rest = strings.TrimSpace(after[end+1:])
		if rest != "" {
			if rest, ok = strings.CutPrefix(rest, ","); !ok {
				return nil
			}
		}
	}
	if len(tags) == 0 {
		return nil
	}
	return tags
}
