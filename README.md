# QueryGuard

QueryGuard is a proxy that sits between your applications and PostgreSQL and
speaks the Postgres wire protocol. It estimates what each query will cost before
it runs and gives every tenant a budget, so one tenant's expensive queries can't
starve everyone else.

> **Status:** early development (milestone M1). QueryGuard relays sessions,
> cancel requests and TLS, but does not estimate or limit anything yet.

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

## License

MIT. See [LICENSE](LICENSE).
