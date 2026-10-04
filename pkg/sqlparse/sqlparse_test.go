package sqlparse

import (
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
		{"select * from orders", Query{}},
		{"update orders set total = 0 where id = 1", Query{}},
		{"update orders set total = 0", Query{ChangesEveryRow: true}},
		{"delete from orders", Query{ChangesEveryRow: true}},
		{"delete from orders using customers", Query{ChangesEveryRow: true}},
		{"select 1; delete from orders", Query{ChangesEveryRow: true}},
		{"with gone as (delete from orders returning id) select count(*) from gone", Query{ChangesEveryRow: true}},
		{"explain analyze delete from orders", Query{ChangesEveryRow: true}},
		{"prepare wipe as delete from orders", Query{ChangesEveryRow: true}},
		{"create table notes (id int)", Query{DDL: true}},
		{"create temp table scratch (id int)", Query{DDL: true}},
		{"alter table orders add column note text", Query{DDL: true}},
		{"drop table orders", Query{DDL: true}},
		{"grant select on orders to reporting", Query{DDL: true}},
		{"select * into orders_copy from orders", Query{DDL: true}},
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
		{"vacuum orders", Query{}},
		{"copy orders from stdin", Query{}},
		{"do $$ begin drop table orders; end $$", Query{Do: true}},
		{"select * from billing.invoices join public.orders using (id)", Query{Schemas: []string{"billing", "public"}}},
		{"select * from public.orders o join public.customers c on c.id = o.customer_id", Query{Schemas: []string{"public"}}},
		{"select billing.total(1)", Query{Schemas: []string{"billing"}}},
		{"set search_path to billing, public", Query{Schemas: []string{"billing", "public"}}},
		{`set search_path = "$user", public`, Query{Schemas: []string{"public"}}},
		{"create table billing.notes (id int)", Query{DDL: true, Schemas: []string{"billing"}}},
		{"drop table billing.invoices", Query{DDL: true, Schemas: []string{"billing"}}},
		{"drop function billing.total(int)", Query{DDL: true, Schemas: []string{"billing"}}},
		{"drop schema billing cascade", Query{DDL: true, Schemas: []string{"billing"}}},
		{"create schema billing", Query{DDL: true, Schemas: []string{"billing"}}},
		{"grant select on all tables in schema billing to reporting", Query{DDL: true, Schemas: []string{"billing"}}},
		{"alter table orders set schema billing", Query{DDL: true, Schemas: []string{"billing"}}},
		{"select 'x'::billing.currency", Query{Schemas: []string{"billing"}}},
		{"truncate billing.orders", Query{ChangesEveryRow: true, Schemas: []string{"billing"}}},
		{`select set_config('search_path', 'billing, "$user"', false)`, Query{Schemas: []string{"billing"}}},
		{"select pg_catalog.set_config('search_path', current_setting('app.path'), false)", Query{Schemas: []string{"pg_catalog"}, UnknownSearchPath: true}},
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
