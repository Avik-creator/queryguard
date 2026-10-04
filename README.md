# QueryGuard

QueryGuard is a proxy that sits between your applications and PostgreSQL and
speaks the Postgres wire protocol. It estimates what each query will cost before
it runs and gives every tenant a budget, so one tenant's expensive queries can't
starve everyone else.

> **Status:** early development. The proxy does not work yet; this repository
> currently holds the project setup (milestone M0).

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

## License

MIT. See [LICENSE](LICENSE).
