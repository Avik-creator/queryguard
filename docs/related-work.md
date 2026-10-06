# Related work

Every piece of QueryGuard exists somewhere. None of the projects below
combines calibrated cost budgets, fair queueing and plan-flip handling in a
proxy for unmodified PostgreSQL, which is why QueryGuard exists. The search
was made in October 2026 and can't rule out small unpublished projects.

## Admission control for PostgreSQL

| Project | Form | What it does | What QueryGuard adds |
| --- | --- | --- | --- |
| PlanetScale Traffic Control | Postgres extension, PlanetScale only | Budgets per workload (burst, server share, concurrency); cost calibrated by a CPU-time-to-cost ratio; targets by role, `application_name`, client address or sqlcommenter tags; warns, or blocks with `53000` | Open source, any PostgreSQL, queueing and a slow lane, plan-flip handling |
| Apache Cloudberry resource queues (Greenplum lineage) | Built into a PostgreSQL fork | Queues per role with `ACTIVE_STATEMENTS` and `MAX_COST`; `COST_OVERCOMMIT` lets costly queries run when the server is idle | Unmodified PostgreSQL; calibrated rather than raw cost |
| pg_plan_filter | Extension (`shared_preload_libraries`) | Refuses statements or transactions above a fixed planner cost | Fairness between tenants, calibration, nothing to install in the server |
| pg_cost_guard | Extension (planner hook) | Refuses queries above a fixed planner cost; warns at 80% of it | Fairness between tenants, calibration, nothing to install in the server |
| pg_QoS | Extension | CPU cores, concurrency and `work_mem` limits per role and database | Decisions per statement, by cost |

Managed services such as RDS, Neon and Supabase don't allow arbitrary
extensions, which is why QueryGuard is a proxy: it needs only a login and,
for most features, `pg_monitor`.

## Proxies and poolers

| Project | Form | What it does | What QueryGuard adds |
| --- | --- | --- | --- |
| PgBouncer | Pooler | Connection pooling; an admin console; peering to forward cancel requests | Cost-based admission. QueryGuard's admin console and cancel forwarding follow PgBouncer's |
| Cloudflare's PgBouncer work | Modified pooler | Throttles connections per tenant; TCP Vegas-style control as future work | Admission by cost rather than by connection |
| PgDog | Rust proxy | Pooling, load balancing, sharding, mirroring | Admission control and tenant budgets |
| PgGateway | Rust proxy, not ready for use | Pooling, routing, rate limiting, query blocking | Scheduling by cost |
| Aperture | SDK and sidecar | Weighted fair queueing and adaptive concurrency for services | No application changes; cost the database knows |

QueryGuard doesn't pool: each client gets its own server connection. When
connections are the problem, put PgBouncer behind it.

## Admission control in other databases

| System | What QueryGuard takes from it |
| --- | --- |
| CockroachDB admission control | Queues per tenant, the tenant with the least recent use admitted first |
| Oracle Resource Manager | Moving a long statement to another consumer group (the slow lane's `demote_after`); plans by time of day (planned for v1.1) |
| SQL Server Resource Governor, TiDB resource control | Budgets and priorities per workload |
| Vitess tablet throttler | Holding back best-effort work while replicas lag |
| PlanetScale's job queue study | Limiting the workload whose old snapshot pins the MVCC horizon while a queue bloats |

## Ideas borrowed

- Burst and share budgets, the calibration ratio and tags to target
  workloads: PlanetScale Traffic Control.
- Cost overcommit, as the slow lane: Greenplum and Cloudberry.
- Latency-based concurrency limits (AIMD): Netflix's concurrency-limits and
  Cloudflare's future work.
- Adaptive LIFO with CoDel for queues under overload: Facebook's "Fail at
  Scale".
- Leasing shares of a global limit from a store: YouTube's Doorman.
- Deadlines that travel with a request: gRPC.
- Credibility weighting of a plan's own timing against the server's:
  Bühlmann's formula from actuarial science.
- Read-only bypasses for the AI-agent preset's corpus: the 2026 reports
  against Postgres MCP servers.
- Query stats by fingerprint and anomaly baselines: pg_stat_statements,
  pganalyze and PlanetScale Insights.
