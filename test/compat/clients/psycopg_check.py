"""Runs psycopg 3 through QueryGuard: plaintext, TLS, direct TLS, parameters, cancel keys, cancel and rule rejections."""

import os
import sys
import threading

import psycopg
from psycopg import errors

PLAIN = f"host={os.environ['QG_HOST']} port={os.environ['QG_PORT']} user=postgres dbname=queryguard sslmode=disable"
TLS = f"host=localhost port={os.environ['QG_PORT']} user=postgres dbname=queryguard sslmode=verify-full sslrootcert={os.environ['QG_CA']}"
# QG_RULES_PORT blocks DELETE without WHERE; the table doesn't exist, so a missed rejection fails with 42P01 instead.
RULES = f"host={os.environ['QG_HOST']} port={os.environ['QG_RULES_PORT']} user=postgres dbname=queryguard sslmode=disable"
# QG_COST_PORT blocks statements planned to cost more than half a full read of orders, such as that read.
COST = f"host={os.environ['QG_HOST']} port={os.environ['QG_COST_PORT']} user=postgres dbname=queryguard sslmode=disable"
BLOCKED = "delete from qg_no_such_table"
LIBPQ = psycopg.pq.version()

failed = False


def check(name, fn):
    global failed
    try:
        fn()
        print(f"ok   {name}")
    except Exception as err:
        print(f"FAIL {name}: {err!r}")
        failed = True


def select_one(conninfo):
    with psycopg.connect(conninfo) as conn:
        assert conn.execute("select 1").fetchone()[0] == 1


def tls_in_use():
    with psycopg.connect(TLS) as conn:
        assert conn.pgconn.ssl_in_use, "connection is not encrypted"


def parameters():
    with psycopg.connect(PLAIN) as conn:
        total = conn.execute("select %s::int + %s::int", (2, 3)).fetchone()[0]
        assert total == 5, f"2 + 3 returned {total}"


def proxy_cancel_key():
    with psycopg.connect(PLAIN) as conn:
        real = conn.execute("select pg_backend_pid()").fetchone()[0]
        assert conn.info.backend_pid != real, f"client was given the real backend pid {real}"


def cancel(conninfo):
    def run():
        with psycopg.connect(conninfo) as conn:
            problems = []

            def send_cancel():
                # cancel_safe uses libpq's newer cancel API, which encrypts the cancel request when the session is TLS.
                try:
                    conn.cancel_safe()
                except Exception as err:
                    problems.append(err)

            timer = threading.Timer(0.3, send_cancel)
            timer.start()
            try:
                conn.execute("select pg_sleep(30)")
                raise AssertionError("pg_sleep(30) finished without being cancelled")
            except errors.QueryCanceled:
                pass
            finally:
                timer.join()
            if problems:
                raise problems[0]

    return run


def expect_rejected(fn):
    try:
        fn()
    except errors.InsufficientPrivilege as err:
        assert "require_where" in str(err), f"rejected for another reason: {err}"
        return
    raise AssertionError("statement ran; want 42501 from rule require_where")


def rejected_statement():
    with psycopg.connect(RULES, autocommit=True) as conn:
        # prepare=True makes psycopg send a named Parse, as it does for statements it runs often.
        for prepare in (False, True):
            expect_rejected(lambda: conn.execute(BLOCKED, prepare=prepare))
            assert conn.execute("select 1").fetchone()[0] == 1


def rejection_fails_transaction():
    with psycopg.connect(RULES) as conn:
        conn.execute("select 1")
        expect_rejected(lambda: conn.execute(BLOCKED))
        try:
            conn.execute("select 1")
            raise AssertionError("statement after the rejection ran")
        except errors.InFailedSqlTransaction:
            pass
        conn.rollback()
        assert conn.execute("select 1").fetchone()[0] == 1


def rejection_in_pipeline():
    with psycopg.connect(RULES, autocommit=True) as conn:
        conn.execute("create temp table qg_pipeline (id int)")

        def run():
            with conn.pipeline():
                conn.execute("insert into qg_pipeline values (1)")
                conn.execute("delete from qg_pipeline")

        expect_rejected(run)
        rows = conn.execute("select count(*) from qg_pipeline").fetchone()[0]
        assert rows == 0, f"table has {rows} rows; want the insert rolled back with the rejected delete"


def costly_statement():
    with psycopg.connect(COST, autocommit=True) as conn:
        for prepare in (False, True):
            try:
                conn.execute("select count(*) from orders where note = %s", ["x"], prepare=prepare)
                raise AssertionError("costly statement ran; want 54000 from rule max_cost")
            except errors.ProgramLimitExceeded as err:
                assert "max_cost" in str(err), f"rejected for another reason: {err}"
            assert conn.execute("select id from orders where id = %s", [7], prepare=prepare).fetchone()[0] == 7


print(f"psycopg {psycopg.__version__}, libpq {LIBPQ}")
check("plaintext", lambda: select_one(PLAIN))
check("SSLRequest", tls_in_use)
if LIBPQ >= 170000:
    check("direct TLS", lambda: select_one(TLS + " sslnegotiation=direct"))
if LIBPQ >= 180000:
    check("protocol 3.2 over TLS", lambda: select_one(TLS + " max_protocol_version=3.2"))
check("parameters", parameters)
check("proxy-issued cancel key", proxy_cancel_key)
check("cancel", cancel(PLAIN))
check("cancel over TLS", cancel(TLS))
check("rejected statement", rejected_statement)
check("rejection fails the transaction", rejection_fails_transaction)
check("rejected statement in a pipeline", rejection_in_pipeline)
check("costly statement", costly_statement)
sys.exit(1 if failed else 0)
