# QueryGuard

QueryGuard is a proxy that sits between your applications and PostgreSQL and
speaks the Postgres wire protocol. It estimates what each query will cost before
it runs and gives every tenant a budget, so one tenant's expensive queries can't
starve everyone else.

> **Status:** early development. Milestone M1, a transparent proxy, is done:
> QueryGuard relays sessions, cancel requests and TLS, but does not estimate
> or limit anything yet.

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
| pgx 5.11 | plaintext, TLS, direct TLS, protocol 3.2, prepared statements, COPY, cancel on 3.0, 3.2 and 3.2 over TLS |
| psql 18 | plaintext, TLS, direct TLS, protocol 3.2, Ctrl-C |
| node-postgres 8 | plaintext, TLS, parameters, cancel |
| psycopg 3.3 (libpq 18) | plaintext, TLS, direct TLS, protocol 3.2, parameters, cancel, cancel over TLS |

Every client also checks that its cancel key is the proxy's own, not the
server's.

## Overhead

`make overhead` times 5,000 runs of each query straight to PostgreSQL and
through QueryGuard. Ranges are over three runs on an Apple M1, with
PostgreSQL 18 in Docker (OrbStack) and the proxy in the benchmark's process:

| Query | Path | p50 | p99 |
| --- | --- | --- | --- |
| `select 1` | direct | 116–138 µs | 190–437 µs |
| `select 1` | QueryGuard | 156–159 µs | 240–244 µs |
| `select 1` | QueryGuard, TLS from the client | 153–158 µs | 219–257 µs |
| 1,000 rows (about 50 KB) | direct | 933–936 µs | 1,197–1,324 µs |
| 1,000 rows (about 50 KB) | QueryGuard | 1,043–1,106 µs | 1,318–1,462 µs |
| 1,000 rows (about 50 KB) | QueryGuard, TLS from the client | 1,030–1,088 µs | 1,293–1,460 µs |

The proxy adds about 20–40 µs to a round trip at p50, and 11–18% to the
1,000-row result. TLS from the client adds nothing measurable here. These are
laptop numbers; the full benchmark matrix comes with v1.0.

## License

MIT. See [LICENSE](LICENSE).
