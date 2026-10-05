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
	Explainable         bool     // a single statement EXPLAIN can plan: SELECT, INSERT, UPDATE, DELETE, MERGE, DECLARE or CREATE TABLE AS
	Analyzes            bool     // VACUUM or ANALYZE, which refresh the planner's statistics
	Cursor              bool     // DECLARE, whose query runs in the FETCHes that follow
}

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
	if len(tree.Stmts) == 1 {
		switch tree.Stmts[0].GetStmt().GetNode().(type) {
		case *pg_query.Node_SelectStmt, *pg_query.Node_InsertStmt, *pg_query.Node_UpdateStmt, *pg_query.Node_DeleteStmt,
			*pg_query.Node_MergeStmt, *pg_query.Node_DeclareCursorStmt, *pg_query.Node_CreateTableAsStmt:
			q.Explainable = true
		}
		_, q.Cursor = tree.Stmts[0].GetStmt().GetNode().(*pg_query.Node_DeclareCursorStmt)
	}
	schemas := map[string]bool{}
	add := func(schema string) {
		if schema != "" {
			schemas[schema] = true
		}
	}
	walk(tree.ProtoReflect(), func(m protoreflect.Message) {
		if name := m.Descriptor().Name(); strings.HasSuffix(string(name), "Stmt") && !notDDL[name] {
			q.DDL = true
		}
		switch n := m.Interface().(type) {
		case *pg_query.SelectStmt:
			// SELECT INTO creates a table.
			q.DDL = q.DDL || n.IntoClause != nil
		case *pg_query.UpdateStmt:
			q.ChangesEveryRow = q.ChangesEveryRow || n.WhereClause == nil
			// Updating the pg_settings view calls set_config for each row, with names and values known only when it runs.
			if r := n.GetRelation(); r.GetRelname() == "pg_settings" && (r.GetSchemaname() == "" || r.GetSchemaname() == "pg_catalog") {
				q.UnknownSearchPath = true
			}
		case *pg_query.DeleteStmt:
			q.ChangesEveryRow = q.ChangesEveryRow || n.WhereClause == nil
		case *pg_query.TruncateStmt:
			q.ChangesEveryRow = true
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
		case *pg_query.VacuumStmt:
			q.Analyzes = true
		case *pg_query.RangeVar:
			add(n.Schemaname)
		case *pg_query.FuncCall:
			add(schemaOf(n.Funcname))
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
	q.Schemas = slices.Sorted(maps.Keys(schemas))
	return q, nil
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
