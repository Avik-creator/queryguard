#!/bin/sh
# Runs psql through QueryGuard: plaintext, TLS, direct TLS, protocol 3.2, Ctrl-C and rule rejections.
set -eu

plain="host=$QG_HOST port=$QG_PORT user=postgres dbname=queryguard sslmode=disable"
rules="host=$QG_HOST port=$QG_RULES_PORT user=postgres dbname=queryguard sslmode=disable"
tls="host=localhost port=$QG_PORT user=postgres dbname=queryguard sslmode=verify-full sslrootcert=$QG_CA"
failed=0

check() {
	name=$1
	conninfo=$2
	got=$(psql "$conninfo" -XAtc "select 'ok'" 2>&1) || true
	if [ "$got" = ok ]; then echo "ok   $name"; else echo "FAIL $name: $got"; failed=1; fi
}

psql --version
check "plaintext" "$plain"
check "SSLRequest" "$tls"
check "direct TLS" "$tls sslnegotiation=direct"
check "protocol 3.2 over TLS" "$tls max_protocol_version=3.2"

# psql sends a CancelRequest when it gets SIGINT, as on Ctrl-C.
got=$(timeout -s INT 1 psql "$tls max_protocol_version=3.2" -Xc "select pg_sleep(30)" 2>&1) || true
case $got in
*"canceling statement due to user request"*) echo "ok   Ctrl-C cancels" ;;
*) echo "FAIL Ctrl-C cancels: $got"; failed=1 ;;
esac

# QG_RULES_PORT blocks DELETE without WHERE; the table doesn't exist, so a missed rejection fails with 42P01 instead.
got=$(psql "$rules" -XAt -c "delete from qg_no_such_table" -c "select 'ok'" 2>&1) || true
case $got in
*"rule require_where blocks this statement"*ok) echo "ok   rejected statement" ;;
*) echo "FAIL rejected statement: $got"; failed=1 ;;
esac

got=$(psql "$rules" -XAt -c "begin" -c "delete from qg_no_such_table" -c "select 1" -c "rollback" -c "select 'ok'" 2>&1) || true
case $got in
*"require_where"*"current transaction is aborted"*ok) echo "ok   rejection fails the transaction" ;;
*) echo "FAIL rejection fails the transaction: $got"; failed=1 ;;
esac

exit $failed
