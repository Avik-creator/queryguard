package sqlparse

import (
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

func TestAnalyze(t *testing.T) {
	for _, tc := range []struct {
		sql  string
		want Query
	}{
		{"select * from orders", Query{Explainable: true}},
		{"update orders set total = 0 where id = 1", Query{Explainable: true}},
		{"update orders set total = 0", Query{ChangesEveryRow: true, Explainable: true}},
		{"delete from orders", Query{ChangesEveryRow: true, Explainable: true}},
		{"delete from orders using customers", Query{ChangesEveryRow: true, Explainable: true}},
		{"select 1; delete from orders", Query{ChangesEveryRow: true}},
		{"with gone as (delete from orders returning id) select count(*) from gone", Query{ChangesEveryRow: true, Explainable: true}},
		{"explain analyze delete from orders", Query{ChangesEveryRow: true}},
		{"prepare wipe as delete from orders", Query{ChangesEveryRow: true}},
		{"create table notes (id int)", Query{DDL: true}},
		{"create temp table scratch (id int)", Query{DDL: true}},
		{"alter table orders add column note text", Query{DDL: true}},
		{"drop table orders", Query{DDL: true}},
		{"grant select on orders to reporting", Query{DDL: true}},
		{"select * into orders_copy from orders", Query{DDL: true, Explainable: true}},
		{"explain analyze create table orders_copy as select * from orders", Query{DDL: true}},
		{"create index on orders (customer_id)", Query{DDL: true, BlockingIndexChange: true}},
		{"create index concurrently on orders (customer_id)", Query{DDL: true}},
		// ON ONLY builds nothing; it is the first step of indexing a partitioned table without blocking writes.
		{"create index on only events (customer_id)", Query{DDL: true}},
		{"drop index orders_customer_idx", Query{DDL: true, BlockingIndexChange: true}},
		{"drop index concurrently orders_customer_idx", Query{DDL: true}},
		{"reindex index orders_customer_idx", Query{BlockingIndexChange: true}},
		{"reindex table concurrently orders", Query{}},
		{"truncate orders", Query{ChangesEveryRow: true}},
		{"begin", Query{}},
		{"set statement_timeout = 0", Query{}},
		{"vacuum orders", Query{Analyzes: true}},
		{"analyze orders", Query{Analyzes: true}},
		{"copy orders from stdin", Query{}},
		{"do $$ begin drop table orders; end $$", Query{Opaque: true}},
		// A procedure's body can run DDL or change every row, which its CALL doesn't show.
		{"call billing.purge(1)", Query{Opaque: true, Schemas: []string{"billing"}}},
		{"insert into orders (id) values (1)", Query{Explainable: true}},
		{"merge into orders o using customers c on c.id = o.id when matched then delete", Query{Explainable: true}},
		{"declare c cursor for select * from orders", Query{Explainable: true, Cursor: true}},
		{"create table orders_copy as select * from orders", Query{DDL: true, Explainable: true}},
		// EXECUTE runs a statement prepared earlier in the session, so its text says nothing about its plan.
		{"execute wipe(1)", Query{}},
		{"select 1;", Query{Explainable: true}},
		{"select * from billing.invoices join public.orders using (id)", Query{Schemas: []string{"billing", "public"}, Explainable: true}},
		{"select * from public.orders o join public.customers c on c.id = o.customer_id", Query{Schemas: []string{"public"}, Explainable: true}},
		{"select billing.total(1)", Query{Schemas: []string{"billing"}, Explainable: true}},
		{"set search_path to billing, public", Query{Schemas: []string{"billing", "public"}}},
		{`set search_path = "$user", public`, Query{Schemas: []string{"public"}}},
		{"create table billing.notes (id int)", Query{DDL: true, Schemas: []string{"billing"}}},
		{"drop table billing.invoices", Query{DDL: true, Schemas: []string{"billing"}}},
		{"drop function billing.total(int)", Query{DDL: true, Schemas: []string{"billing"}}},
		{"drop schema billing cascade", Query{DDL: true, Schemas: []string{"billing"}}},
		{"create schema billing", Query{DDL: true, Schemas: []string{"billing"}}},
		{"grant select on all tables in schema billing to reporting", Query{DDL: true, Schemas: []string{"billing"}}},
		{"alter table orders set schema billing", Query{DDL: true, Schemas: []string{"billing"}}},
		{"select 'x'::billing.currency", Query{Schemas: []string{"billing"}, Explainable: true}},
		{"truncate billing.orders", Query{ChangesEveryRow: true, Schemas: []string{"billing"}}},
		{`select set_config('search_path', 'billing, "$user"', false)`, Query{Schemas: []string{"billing"}, Explainable: true}},
		{"select pg_catalog.set_config('search_path', current_setting('app.path'), false)", Query{Schemas: []string{"pg_catalog"}, UnknownSearchPath: true, Explainable: true}},
		// Postgres looks setting names up ignoring case.
		{`set "SEARCH_PATH" = billing`, Query{Schemas: []string{"billing"}}},
		{"select set_config('SEARCH_PATH', 'billing', false)", Query{Schemas: []string{"billing"}, Explainable: true}},
		{"select set_config(lower('SEARCH_PATH'), 'billing', false)", Query{UnknownSearchPath: true, Explainable: true}},
		{"select set_config('application_name', 'billing', false)", Query{Explainable: true}},
		// Updating pg_settings calls set_config for each row.
		{"update pg_settings set setting = 'billing' where name = 'search_path'", Query{UnknownSearchPath: true, Explainable: true}},
		{"update pg_catalog.pg_settings set setting = 'billing' where name = 'search_path'", Query{Schemas: []string{"pg_catalog"}, UnknownSearchPath: true, Explainable: true}},
	} {
		got, err := Analyze(tc.sql)
		if err != nil {
			t.Errorf("Analyze(%q): %v", tc.sql, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Analyze(%q) = %+v; want %+v", tc.sql, got, tc.want)
		}
	}
}

// postgresDDL lists the statement types GetCommandLogLevel logs as LOGSTMT_DDL in src/backend/tcop/utility.c of
// Postgres 17 (unchanged in 18), apart from SelectStmt, which is DDL only with INTO.
var postgresDDL = []string{
	"AlterCollationStmt",
	"AlterDatabaseRefreshCollStmt",
	"AlterDatabaseSetStmt",
	"AlterDatabaseStmt",
	"AlterDefaultPrivilegesStmt",
	"AlterDomainStmt",
	"AlterEnumStmt",
	"AlterEventTrigStmt",
	"AlterExtensionContentsStmt",
	"AlterExtensionStmt",
	"AlterFdwStmt",
	"AlterForeignServerStmt",
	"AlterFunctionStmt",
	"AlterObjectDependsStmt",
	"AlterObjectSchemaStmt",
	"AlterOpFamilyStmt",
	"AlterOperatorStmt",
	"AlterOwnerStmt",
	"AlterPolicyStmt",
	"AlterPublicationStmt",
	"AlterRoleSetStmt",
	"AlterRoleStmt",
	"AlterSeqStmt",
	"AlterStatsStmt",
	"AlterSubscriptionStmt",
	"AlterSystemStmt",
	"AlterTSConfigurationStmt",
	"AlterTSDictionaryStmt",
	"AlterTableMoveAllStmt",
	"AlterTableSpaceOptionsStmt",
	"AlterTableStmt",
	"AlterTypeStmt",
	"AlterUserMappingStmt",
	"ClusterStmt",
	"CommentStmt",
	"CompositeTypeStmt",
	"CreateAmStmt",
	"CreateCastStmt",
	"CreateConversionStmt",
	"CreateDomainStmt",
	"CreateEnumStmt",
	"CreateEventTrigStmt",
	"CreateExtensionStmt",
	"CreateFdwStmt",
	"CreateForeignServerStmt",
	"CreateForeignTableStmt",
	"CreateFunctionStmt",
	"CreateOpClassStmt",
	"CreateOpFamilyStmt",
	"CreatePLangStmt",
	"CreatePolicyStmt",
	"CreatePublicationStmt",
	"CreateRangeStmt",
	"CreateRoleStmt",
	"CreateSchemaStmt",
	"CreateSeqStmt",
	"CreateStatsStmt",
	"CreateStmt",
	"CreateSubscriptionStmt",
	"CreateTableAsStmt",
	"CreateTableSpaceStmt",
	"CreateTransformStmt",
	"CreateTrigStmt",
	"CreateUserMappingStmt",
	"CreatedbStmt",
	"DefineStmt",
	"DropOwnedStmt",
	"DropRoleStmt",
	"DropStmt",
	"DropSubscriptionStmt",
	"DropTableSpaceStmt",
	"DropUserMappingStmt",
	"DropdbStmt",
	"GrantRoleStmt",
	"GrantStmt",
	"ImportForeignSchemaStmt",
	"IndexStmt",
	"ReassignOwnedStmt",
	"RefreshMatViewStmt",
	"RenameStmt",
	"RuleStmt",
	"SecLabelStmt",
	"ViewStmt",
}

func TestDDLMatchesPostgres(t *testing.T) {
	msgs := pg_query.File_pg_query_proto.Messages()
	for i := range msgs.Len() {
		name := msgs.Get(i).Name()
		if !strings.HasSuffix(string(name), "Stmt") {
			continue
		}
		// A new statement type after a parser upgrade fails here until it is checked against utility.c.
		if got, want := !notDDL[name], slices.Contains(postgresDDL, string(name)); got != want {
			t.Errorf("%s counts as DDL = %v; Postgres says %v", name, got, want)
		}
	}
}

func TestBackslashInString(t *testing.T) {
	for sql, want := range map[string]bool{
		`select 'plain'`:                       false,
		`select 'a\b'`:                         true,
		`select '\''; delete from orders; --'`: true,
		`select E'a\b', e'\''`:                 false,
		`select $$a\b$$, $x$\$x$`:              false,
		`select "a\b" from orders -- \`:        false,
		`select 1 /* \' */`:                    false,
		`select U&'d\0061t\+000061'`:           true,
		`select '\`:                            true,
	} {
		if got := BackslashInString(sql); got != want {
			t.Errorf("BackslashInString(%q) = %v; want %v", sql, got, want)
		}
	}
}

func TestTags(t *testing.T) {
	for sql, want := range map[string]map[string]string{
		`select 1 /*tenant='acme',route='%2Forders'*/`: {"tenant": "acme", "route": "/orders"},
		`select 1 /*a='1'*/ /*tenant='b'*/`:            {"tenant": "b"},
		`select 1 /*name='O\'Brien',x%20y='a%2Cb'*/`:   {"name": "O'Brien", "x y": "a,b"},
		`select 1`:                          nil,
		`select 1 /*just a note*/`:          nil,
		`select 1 /*tenant='acme',broken*/`: nil,
		`select 1 -- tenant='acme'`:         nil,
		`select '/*tenant=''acme''*/'`:      nil,
		`select 1 /*tenant='%zz'*/`:         nil,
		`select 'unterminated`:              nil,
	} {
		if got := Tags(sql); !maps.Equal(got, want) {
			t.Errorf("Tags(%q) = %v; want %v", sql, got, want)
		}
	}
}

func TestAnalyzeRejectsInvalidSQL(t *testing.T) {
	if _, err := Analyze("selec 1"); err == nil {
		t.Error("Analyze(selec 1) succeeded; want a syntax error")
	}
}

func TestFingerprintIgnoresConstants(t *testing.T) {
	a, b := Fingerprint("select * from orders where id = 1"), Fingerprint("select * from orders where id = 2")
	if a == "" || a != b {
		t.Errorf("fingerprints %q and %q; want the same non-empty value", a, b)
	}
}
