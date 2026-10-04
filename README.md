# QueryGuard

QueryGuard is a proxy that sits between your applications and PostgreSQL and
speaks the Postgres wire protocol. It estimates what each query will cost before
it runs and gives every tenant a budget, so one tenant's expensive queries can't
starve everyone else.

> **Status:** early development. Milestones M1 (a transparent proxy) and M2
> (rules and connection caps) are done: QueryGuard relays sessions, cancel
> requests and TLS, and can block statements by rule, but does not estimate
> cost or enforce budgets yet.

## Planned features

- Tenants identified by database role, or by a sqlcommenter tag sent from a
  trusted role.
- Cost estimates from an inline `EXPLAIN`, corrected over time by comparing
  them with how long queries actually took.
- Per-tenant budgets with a burst limit and a share of the server. Queries
  over budget are queued, sent to a slow lane or rejected.
- Rules in warn or enforce mode, matching on role, `application_name`, client
  address or tags.
- Prometheus metrics and a log of every decision.

## Requirements

- Go 1.27 or later
- PostgreSQL 16, 17 or 18 (19 is experimental)

## Build

```sh
go build -o bin/queryguard ./cmd/queryguard
./bin/queryguard -version
```

## TLS

Clients can use TLS through an `SSLRequest` or, from PostgreSQL 17 clients,
`sslnegotiation=direct`:

```sh
make certs   # self-signed certificate for local testing
./bin/queryguard -tls-cert certs/server.crt -tls-key certs/server.key
```

TLS to PostgreSQL is set with `-upstream-sslmode` (`disable`, `require` or
`verify-full`, with the same meanings as in libpq) and `-upstream-ca` for a
private CA.

### SCRAM channel binding

Channel binding (`SCRAM-SHA-256-PLUS`) ties the password check to the server's
TLS certificate. The client sees QueryGuard's certificate while PostgreSQL
checks its own, so with TLS on both sides:

| QueryGuard's certificate | Clients with `channel_binding=prefer` (the libpq default) |
| --- | --- |
| The same certificate and key as PostgreSQL | Work, with channel binding end to end |
| A different certificate | Fail with "SCRAM channel binding negotiation error"; set `channel_binding=disable` |

Clients connecting to QueryGuard without TLS always work.

## Rules

Start QueryGuard with `-config queryguard.json` to check every statement
before it reaches PostgreSQL:

```json
{
  "rules": [
    {"check": "deny_ddl"},
    {"check": "require_where"},
    {"check": "index_concurrently", "mode": "warn"},
    {"check": "schema_allowlist", "schemas": ["public", "app"]}
  ],
  "max_connections": 200,
  "tenant_max_connections": 20,
  "tenants": {
    "reporting": {"mode": "warn"},
    "batch": {"max_connections": 5}
  }
}
```

| Check | Blocks |
| --- | --- |
| `deny_ddl` | Statements PostgreSQL logs as DDL under `log_statement = 'ddl'`, `SELECT INTO`, and `DO` blocks |
| `require_where` | `UPDATE` or `DELETE` without `WHERE`, and `TRUNCATE`; `WHERE true` changes every row on purpose |
| `index_concurrently` | `CREATE INDEX`, `DROP INDEX` and `REINDEX` without `CONCURRENTLY`; `CREATE INDEX ON ONLY`, the first step in indexing a partitioned table, is allowed |
| `schema_allowlist` | Naming a schema outside `schemas`, in a statement or in `search_path`, including a `search_path` set at login; `pg_catalog`, `information_schema` and the session's temporary schema are always allowed |

Every statement in a query string is checked, including those inside CTEs,
`EXPLAIN` and `PREPARE`. A rule, or a tenant (keyed by role), in `warn` mode
only logs what it would have rejected.

A rejected statement fails with SQLSTATE `42501` and a hint, and the
connection stays usable. Outside a transaction QueryGuard answers it itself;
inside a transaction or a pipeline it has PostgreSQL raise the error, so the
transaction fails and the pipeline's earlier statements roll back, as after
any other error. The log line names the rule and carries the statement's
fingerprint and its text without constants; the error carries only the
fingerprint.

### Statements that can't be checked

QueryGuard reads SQL with pg_query, the PostgreSQL 17 parser. By default it
rejects a statement it cannot check, with the reason in the error's detail:

- SQL the parser can't read, including syntax newer than PostgreSQL 17
- a statement over 16 MB
- a backslash inside a plain string while `standard_conforming_strings` is
  off, or non-ASCII text while `client_encoding` is not `UTF8`, since
  PostgreSQL may then read the text differently from the parser. While an
  earlier statement in a pipeline is still running, QueryGuard can't know
  these settings yet and treats them as unknown.

`"unchecked": "allow"` lets these statements run and logs them, but then any
rule can be sidestepped by writing a statement the parser can't read.

### What rules are not

Rules catch mistakes, such as a forgotten `WHERE` or an index build that
blocks writes to a busy table. They are not a security boundary: functions,
views and triggers run SQL that QueryGuard never sees. Grant each role only
the privileges it needs in PostgreSQL itself.

## Connection caps

`max_connections` caps all sessions through QueryGuard, `tenant_max_connections`
caps each role, and a tenant's own `max_connections` replaces that cap for its
role; `0` or no value means no cap. As with PostgreSQL's own limits, a session
counts once it has logged in, and one over a cap gets FATAL `53300`
(`too_many_connections`) just after authentication.

## Connections that die silently

When a machine or network goes away without closing its connections, neither
end notices for a long time: on Linux, TCP keepalive gives up after about
2 hours 11 minutes. QueryGuard sets keepalive on client connections and on its
connections to PostgreSQL to probe after 15 seconds of silence, every
5 seconds, and give up after 3, so a dead peer is found in about 30 seconds.
On Linux it also sets `TCP_USER_TIMEOUT`, which covers data that is never
acknowledged.

It sends PostgreSQL the same timing for the server's end of each session, as
`tcp_keepalives_idle`, `tcp_keepalives_interval`, `tcp_keepalives_count` and
`tcp_user_timeout`, unless the client set them. `-tcp-keepalive=false` keeps
the operating system's timing.

## Clients that disconnect mid-query

PostgreSQL normally keeps running a query after its client has gone, until
the query next reads or writes the socket. QueryGuard sends
`client_connection_check_interval=2000` with each new session, so the query
stops within about 2 seconds. A value the client sets, directly or in
`options`, is kept. Change it with `-client-check-interval`; `0` leaves the
server's setting alone, and is needed on platforms where PostgreSQL rejects a
non-zero value.

## Compatibility

`make compat` runs these clients through QueryGuard against a real PostgreSQL
(`PG=16`, `17` or `18`; start the servers with `make up`), and CI runs it on
all three versions:

| Client | Checked |
| --- | --- |
| pgx 5.11 | plaintext, TLS, direct TLS, protocol 3.2, prepared statements, COPY, cancel on 3.0, 3.2 and 3.2 over TLS, keepalive settings; rejections in all three query modes, in a transaction and in a pipeline; warn mode; connection cap |
| psql 18 | plaintext, TLS, direct TLS, protocol 3.2, Ctrl-C; rejection, in a transaction |
| node-postgres 8 | plaintext, TLS, parameters, cancel; rejection, in a transaction |
| psycopg 3.3 (libpq 18) | plaintext, TLS, direct TLS, protocol 3.2, parameters, cancel, cancel over TLS; rejection, in a transaction and in a pipeline |

Every client also checks that its cancel key is the proxy's own, not the
server's, and that the connection stays usable after a rejection.

## Overhead

`make overhead` times 5,000 runs of each query straight to PostgreSQL and
through QueryGuard, without rules and with the rules from the compatibility
tests. Ranges are over three runs on an Apple M1, with PostgreSQL 18 in Docker
(OrbStack) and the proxy in the benchmark's process:

| Query | Path | p50 | p99 |
| --- | --- | --- | --- |
| `select 1` | direct | 113–134 µs | 275–362 µs |
| `select 1` | QueryGuard | 144–163 µs | 231–332 µs |
| `select 1` | QueryGuard, TLS from the client | 158–168 µs | 255–416 µs |
| `select 1` | QueryGuard with rules | 160–163 µs | 236–320 µs |
| `select 1` | QueryGuard with rules, simple protocol | 155–180 µs | 205–351 µs |
| 1,000 rows (about 50 KB) | direct | 925–989 µs | 1,157–1,481 µs |
| 1,000 rows (about 50 KB) | QueryGuard | 1,029–1,056 µs | 1,210–1,516 µs |
| 1,000 rows (about 50 KB) | QueryGuard, TLS from the client | 1,045–1,092 µs | 1,462–1,597 µs |
| 1,000 rows (about 50 KB) | QueryGuard with rules | 1,037–1,039 µs | 1,457–1,913 µs |
| 1,000 rows (about 50 KB) | QueryGuard with rules, simple protocol | 1,092–1,173 µs | 1,458–4,524 µs |

The proxy adds about 20–40 µs to a round trip at p50, and 4–14% to the
1,000-row result. pgx prepares each statement once, so with rules on only the
first run is parsed and checked. With the simple protocol every run is, and
p50 rose by up to about 20 µs for `select 1` and 120 µs for the 1,000-row
query. The 4.5 ms p99 came from one noisy
run; the other two were 1.5–1.8 ms. These are laptop numbers; the full
benchmark matrix comes with v1.0.

## License

MIT. See [LICENSE](LICENSE).
