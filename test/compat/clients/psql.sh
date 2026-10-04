#!/bin/sh
# Runs psql through QueryGuard: plaintext, TLS, direct TLS, protocol 3.2 and Ctrl-C.
set -eu

plain="host=$QG_HOST port=$QG_PORT user=postgres dbname=queryguard sslmode=disable"
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

exit $failed
