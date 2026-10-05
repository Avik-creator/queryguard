# QueryGuard

QueryGuard is a proxy that sits between your applications and PostgreSQL and
speaks the Postgres wire protocol. It estimates what each query will cost before
it runs and gives every tenant a budget, so one tenant's expensive queries can't
starve everyone else.

> **Status:** early development. Milestones M1 to M6 are done: QueryGuard
> relays sessions, cancel requests and TLS; blocks statements by rule or by
> their planned cost; gives each tenant a cost budget, a fair share of the
> server and time limits; learns from how long statements take, to correct
> their costs and to catch plans that suddenly get worse; and adapts to the
> server's load, cancels DDL stuck in a lock queue, and shares its limits
> across instances.

## Planned features

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

PostgreSQL sees every client as the proxy: `pg_hba.conf` rules match
QueryGuard's address, and `hostssl` is met by QueryGuard's own connection,
not the client's. Start QueryGuard with `-require-client-tls` to refuse logins
without TLS, so passwords never cross the network in plaintext; cancel
requests, which carry no password, are still accepted without it.

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
| `deny_ddl` | Statements PostgreSQL logs as DDL under `log_statement = 'ddl'`, `SELECT INTO`, `DO` blocks, and `CALL`, since a procedure can run anything |
| `require_where` | `UPDATE` or `DELETE` without `WHERE`, and `TRUNCATE`; `WHERE true` changes every row on purpose |
| `index_concurrently` | `CREATE INDEX`, `DROP INDEX` and `REINDEX` without `CONCURRENTLY`; `CREATE INDEX ON ONLY`, the first step in indexing a partitioned table, is allowed |
| `schema_allowlist` | Naming a schema outside `schemas`, in a statement or in `search_path`, including a `search_path` set at login; `pg_catalog`, `information_schema` and the session's temporary schema are always allowed |

Every statement in a query string is checked, including those inside CTEs,
`EXPLAIN` and `PREPARE`. A rule, or a tenant, in `warn` mode only logs what it
would have rejected.

A rule can be narrowed with `match`; every field it sets must match, and a
rule without one applies to everyone:

```json
{"check": "deny_ddl", "match": {
  "roles": ["app"], "tenants": ["acme"], "application_names": ["batch"],
  "clients": ["10.0.0.0/8", "192.168.1.7"], "tags": {"route": "/admin"}
}}
```

`application_name` and tags are set by the client, so they only label a
statement; they are not a way to tell who sent it. A client can change
`application_name` to leave a rule narrowed by it, so use it to aim `warn`
rules, not to limit anyone. Tags narrow a rule only for roles in
`trusted_roles` (see "Tenants, budgets and the scheduler"), which a config
with tag matches must set; for any other role such a rule applies whatever
tags its statements carry, since the client could drop them.

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

## Cost rules

Two more checks judge a statement on its plan, which QueryGuard gets from
PostgreSQL just before the statement runs:

```json
{
  "rules": [
    {"check": "max_cost", "cost": 100000},
    {"check": "max_scan_rows", "rows": 1000000}
  ]
}
```

| Check | Blocks |
| --- | --- |
| `max_cost` | A statement whose planned total cost, in the planner's own units, is over `cost` |
| `max_scan_rows` | A plan that reads more than `rows` rows in full (sequential scans), added up over every table and partition it reads that way; reading a small table in full is the right plan, so only the tables' sizes count, not the scan itself |

A blocked statement fails with SQLSTATE `54000` (`program_limit_exceeded`),
and the detail gives the planned cost or the table's size next to the limit.
Like the other rules, these can run in `warn` mode.

How QueryGuard gets the plan:

- It runs `EXPLAIN (FORMAT JSON, VERBOSE)` on the client's own connection, so
  the plan sees the same role, row-level security, `search_path`, temporary
  tables and settings as the statement. With the extended protocol it
  explains the statement at `Bind`, with the values being bound; values over
  1 MB are not sent twice, and it asks for the generic plan instead. A
  statement with a backslash or non-ASCII text is explained at `Bind` only
  while `standard_conforming_strings` and `client_encoding` are known to be
  what they were at `Parse`, since `EXPLAIN` reads its text again.
- A statement that rules rewrite into several queries has a plan for each;
  their costs and full reads add up.
- Plans are cached for a minute by database, role and statement. While a
  cost rule that blocks applies, the cache key includes the statement's
  values, since a selective value and a common one get very different plans:
  only the same statement with the same values skips `EXPLAIN`. Rules in
  `warn` mode and budgets share one plan across values, keyed by the
  statement's fingerprint. Every minute QueryGuard logs the cache's hit rate
  and the average time spent explaining, which is the latency the cost check
  adds.
- If PostgreSQL refuses the `EXPLAIN`, say because a column doesn't exist, the
  client gets that error as its statement's answer, since the statement would
  have failed the same way. Inside a transaction this fails the transaction,
  just as the statement would have.

Only a query string holding a single `SELECT`, `INSERT`, `UPDATE`, `DELETE`,
`MERGE`, `DECLARE` or `CREATE TABLE AS` is costed: `EXPLAIN` plans one
statement at a time, and a later statement may need what an earlier one
creates. `EXECUTE` of a statement made with SQL `PREPARE`, and the client's own
`EXPLAIN ANALYZE`, are not costed either, and `EXPLAIN` has no time limit of
its own yet.

### Table sizes

`max_scan_rows` reads table sizes (`pg_class.reltuples`) over QueryGuard's own
connection to each database, refreshed every minute. Any role can read
`pg_class`; pass the connection string with `-catalog-dsn`, and the password
in `PGPASSWORD` or a `.pgpass` file. The same connection reads how much of
each table changed since it was last analyzed, for
[stale statistics](#stale-statistics):

```sh
PGPASSWORD=… ./bin/queryguard -config queryguard.json \
  -catalog-dsn "host=db.internal port=5432 user=queryguard_catalog"
```

QueryGuard won't start with `max_scan_rows` and no `-catalog-dsn`. A table
that has never been analyzed has no size yet, and isn't judged.

### Server activity

With `-catalog-dsn`, QueryGuard also reads what the whole server is doing,
once a second, in one round trip on one connection: which backends wait on a
lock and for whom (`pg_blocking_pids`), how far each standby lags
(`pg_stat_replication`), which backend holds the oldest snapshot
(`pg_stat_activity.backend_xmin`) and, on PostgreSQL 19, how long finished
lock waits took (`pg_stat_lock`). Seeing other roles' sessions needs the
`pg_monitor` role:

```sql
CREATE ROLE queryguard_catalog LOGIN PASSWORD '…' IN ROLE pg_monitor;
```

A reading that fails is logged and skipped, and the connection is opened
again for the next one. After three failures in a row QueryGuard acts as if
nothing were happening, so a hold or a cap set from an old reading doesn't
outlast it.

### DDL that waits on a lock

`ALTER TABLE` needs an `ACCESS EXCLUSIVE` lock. Behind a long transaction it
waits, and every statement on the table that comes after it queues behind its
request, so one migration can stop a whole application. With server activity
on, QueryGuard cancels its own sessions' DDL that waits on a lock while other
backends wait behind it, or that waits longer than `lock_timeout` (2s) with
no one behind it:

```json
"ddl_guard": {"mode": "enforce", "lock_timeout": "2s"}
```

The client gets SQLSTATE `55P03` (`lock_not_available`), the error of
PostgreSQL's own `lock_timeout`, which migration tools know to retry. `warn`
only logs what would be cancelled, as does a tenant in warn mode; `off` turns
the guard off. Readings come once a second, so a statement may wait up to
about a second behind the DDL before it is cancelled.

### Standbys that lag

```json
"replication_lag": {"max": "10s"}
```

While any standby's `replay_lag` is over `max`, best-effort statements wait
for a slot however many are free, as Vitess's throttler holds back backfills,
and fail with `53000` after their queue timeout. Other statements run as
before. This and `mvcc_horizon` need no other scheduler setting. Logical replication slots and standbys that only stream WAL to an
archive count too, since they show up in `pg_stat_replication`.

### Old snapshots

A snapshot held open, by a long report or a transaction left idle, stops
vacuum from cleaning up any row that changed since, on every table. A busy
job queue then fills with dead rows, and every poll for the next job reads
through them. With `mvcc_horizon`, once the backend holding the oldest
snapshot has held it longer than `max_age`, and the dead rows of the tables in
`watch` have grown by more than `max_dead_tuples` (1000) since, its tenant
runs one statement at a time until it lets go:

```json
"mvcc_horizon": {"max_age": "1m", "watch": ["public.jobs"], "max_dead_tuples": 10000}
```

Its statements then can't overlap and keep the horizon pinned between them.
Without `watch`, age alone is enough. The watched tables are read in
`-catalog-dsn`'s database. A tenant in warn mode is only logged.

### Blocker pays

Time a tenant's statements spend waiting on another tenant's locks is
charged to the tenant holding them, and given back to the one waiting:
each second of waiting costs what a second of running does on this server,
learned from how statements run. A wait on several backends is split among
them. Only QueryGuard's own sessions are charged; `"blocker_pays": "off"`
under `scheduler` turns it off.

## Tenants, budgets and the scheduler

A tenant is the database role by default. Roles listed in `trusted_roles`,
such as an application's one shared role, can name the tenant of each
statement with a [sqlcommenter](https://google.github.io/sqlcommenter/) tag,
`/*tenant='acme'*/` (the key is `tenant_tag`). A tag from any other role is
ignored and logged.

```json
{
  "trusted_roles": ["app"],
  "scheduler": {"max_active": 16, "queue_timeout": "5s",
                "slow_lane": {"max_active": 2, "queue_timeout": "60s"}},
  "tenant_defaults": {
    "budget": {"rate": 200000, "burst": 1000000, "min_charge": 10},
    "statement_timeout": "30s",
    "idle_in_transaction_timeout": "1m"
  },
  "tenants": {
    "reporting": {"budget": {"rate": 50000, "burst": 500000, "share": 2, "when_over": "slow"}},
    "acme": {"budget": {"rate": 20000, "when_over": "reject"}}
  }
}
```

### Budgets

Each tenant has a bucket of planner cost units that fills at `rate` units a
second, up to `burst`. A statement may start while its tenant owes nothing;
its cost, [calibrated](#calibrated-costs) and at least `min_charge`, is then
taken from the bucket, which
can go below zero, so one large statement isn't starved and the long-run rate
still holds. Once a tenant owes units, what happens to its next statement
depends on `when_over`:

| `when_over` | The statement |
| --- | --- |
| `queue` (the default) | Waits for the bucket to refill; if that would take longer than `queue_timeout`, fails at once |
| `slow` | Runs in the slow lane |
| `reject` | Fails at once |

A statement that fails this way gets SQLSTATE `53000` (`insufficient_resources`).
The budget is looked at before `EXPLAIN`, the costliest step, and charged
once the cost is known, in one step, so statements that arrive together can't
all spend the same budget. Statements `EXPLAIN` can't plan, such as `BEGIN` or
a string of several statements, cost `min_charge`. Plans come from the cache
described under cost rules, explained again about one hit in 100.

### Slots

`max_active` limits how many statements run at once in the fast lane, and
the slow lane has its own limit. When the slots are taken, statements queue,
and each slot that comes free goes to the waiting tenant that has used least
for its `share` lately (use fades with a 10-second half-life). A statement
that finds no slot within its lane's `queue_timeout` fails with `53000`. A
session holds one slot until PostgreSQL has answered everything it sent, so
a pipeline needs just one.

### Transactions and locks

`BEGIN`, `COMMIT`, `ROLLBACK`, `SAVEPOINT` and the like never wait for a
budget or a slot. They do no work of their own, and the slot they would wait
for may be held by a statement waiting on the very locks that the `COMMIT`
would let go.

The same knot can tie up any statement. A transaction updates a row and goes
idle, which frees its slot. Another session takes the last slot and waits on
that row. Now the first transaction's next statement waits for a slot that
only it can free. With server activity on, QueryGuard sees which sessions
others wait on, and lets their statements past every limit, budget and hold,
within about a second. A budget is still charged, so the tenant pays for them
later.

### Queues under overload

Normally the fast lane's queue is first in, first out among equals. Once it
has not been empty for `standing_after` (1s), the server is overloaded rather
than busy for a moment, and the queue changes, as in Facebook's adaptive LIFO
with CoDel: the newest statement goes first, since its client is the likeliest
to still be waiting, and statements that have waited longer than `timeout`
(500ms) are turned away with `53000` when a slot comes free, as is a new
statement that can't get one within `timeout`. Priority and fair share still
come first. The slow lane is meant for long waits and always stays first in,
first out.

```json
"scheduler": {"overload_queue": {"standing_after": "1s", "timeout": "500ms"}}
```

`"mode": "off"` keeps the fast lane first in, first out under any load.

### Deadlines

A statement whose client will have given up before it could end is answered
at once with `57014` instead of being run. Its deadline is the sooner of the
`statement_timeout` the client set at login (in its connection string or
`options`) and a `/*deadline='250ms'*/` tag, counted from when the statement
is sent to run, since a client's time limit covers the time it queues too.
Each execution of a prepared statement starts its own count. Once its plan has run five times, it must also start early enough to
end in its usual time, so a statement that usually takes a second and has
half a second left fails before it is run. Waits for a slot and for a budget
both stop at the deadline. Once the session changes `statement_timeout`
itself, with `SET`, `RESET` or `set_config`, QueryGuard can't know the new
value, so only the tag counts from then on.

### Adaptive limit

With `adaptive`, `max_active` becomes a ceiling, and QueryGuard moves the
fast lane's limit between `floor` and it every second, as TCP's congestion
control does (AIMD: additive increase, multiplicative decrease):

```json
"scheduler": {"max_active": 32, "adaptive": {"floor": 4}}
```

- **Overload** is when the statements that finished in the last second ran,
  on average, more than `max_slowdown` (2) times as long as their plans
  usually take, or when more than `lock_wait_share` (a quarter) of the limit
  waits on locks. The limit is then multiplied by `backoff` (0.9), and drops
  by at least one.
- **Calm and full**: when every slot was taken at some point in a calm
  second in which statements finished, the limit grows by one. A statement
  without a usual time yet still counts as finished. A second in which
  nothing finished leaves the limit alone, since slots held by stuck
  statements say nothing about room for more.
- Otherwise it stays where it is, so a quiet server doesn't drift back to
  the ceiling before the load that needs it.

A statement's usual time is the average of its plan's last 50 runs, once the
plan has run five times, so a slow report is not one tenant's normal
analytics query but statements taking longer than they themselves usually
do. Lock waits come from `pg_stat_activity` over `-catalog-dsn`. A good
ceiling is about four times the database's CPU cores.

### Long statements and the slow lane

With `"demote_after": "10s"` under `scheduler`, a fast-lane statement that
runs longer is counted in the slow lane from then on, as Oracle's Resource
Manager switches consumer groups: its fast slot goes to the next statement
waiting, and the slow lane is that much fuller until it ends. By default
statements stay in the lane they started in.

### Priorities

Each tenant has a `priority`: `critical`, `normal` (the default) or
`best_effort`. When a slot comes free it goes to the highest priority
waiting, and then by fair share. While the adaptive limit is backing off,
best-effort statements are shed: those waiting fail at once, and new ones
run only if a slot is free, else fail with `53000`. The shedding ends when
the limit grows again.

A statement can also carry a `/*priority='best_effort'*/` tag. A trusted
role's tag sets its priority either way; anyone else's can only lower it,
since putting your own statements behind others' is always allowed.

```json
"tenants": {"nightly_export": {"priority": "best_effort"}, "payments": {"priority": "critical"}}
```

### Several instances

QueryGuard instances in front of the same server can share their limits, so a
tenant's budget and the slots hold for the whole fleet however a load balancer
spreads clients. Give each the same config and a database set aside for
QueryGuard:

```sh
./bin/queryguard -config queryguard.json -listen 10.0.0.7:6543 \
  -state-dsn "host=db.internal dbname=queryguard_state user=queryguard" -max-instances 4
```

Every second each instance tells the store, three small tables in that
database, how much of each budget and lane it used, and gets a lease of its
share for 10 seconds, as YouTube's Doorman does: what it asks for plus an even
part of what is spare, or a part in proportion to what it asks when the
instances ask for more than there is. The store hands out shares one instance
at a time under an advisory lock, and only what the others can't be using, so
the shares never add up to more than the limit. Statements only ever touch the
instance's own copy of each budget.

When the store can't be reached, an instance keeps going on as much of its last
share as fits `1/max-instances` of the limit, which the store keeps aside for
it, for a minute after its last lease; then it stops admitting statements that
count against a shared limit until the store is back. Losing the store or an
instance so never admits more than the total. A new instance waits up to two
seconds for its first lease before it accepts connections. QueryGuard creates
the tables itself. They are ordinary logged tables, since a crash or failover
that lost them would let the store hand out again what instances still hold.
`-max-instances` must be the same everywhere and at least the number of
instances, and an instance logs a warning when it sees more.

Slots are leased in whole numbers. With fewer slots in a lane than instances,
some instances hold one and the others none, rather than all of them getting
a fraction that rounds down to nothing. A smaller lease doesn't stop
statements already running, so the store counts the slots an instance reports
in use until they end. A tenant whose budget share is zero on an instance
still asks for a part of it there.

Each instance's cancel keys carry its ID in the fleet, so a cancel request the
load balancer sends to another instance is passed on to the one that owns the
key, at its `-advertise-addr` (by default `-listen`).

### Time limits

- `statement_timeout`: QueryGuard cancels a statement running longer, and
  the client gets SQLSTATE `57014` saying it was the statement timeout. A
  client can't lift it with `SET`, as it could PostgreSQL's own.
- `idle_in_transaction_timeout`: a session left idle in a transaction longer
  is ended with `FATAL 25P03`, and PostgreSQL rolls the transaction back.
- A client that disconnects mid-statement has its statement cancelled, and
  one that disconnects while its statement waits for a slot or a budget never
  has it run.

### Reloading the config

`kill -HUP` makes QueryGuard read its `-config` file again. A file that isn't
valid is logged and ignored, and the one in force stays. A valid one applies
to new and open sessions alike, and tenants keep what they owe and their
recent use.

## Learning from how statements run

QueryGuard times every statement it explains, from when the statement goes to
PostgreSQL until PostgreSQL has answered it, and remembers each statement's
plans by database, role and fingerprint. It explains statements when there
are cost rules, budgets or slots. What it learns is kept in memory, so it
starts again when QueryGuard restarts.

### Calibrated costs

The planner's cost units don't map to the same time for every plan: a
statement whose rows are spread over the disk, or that waits on locks, takes
longer per unit than one reading cached pages in order. For each plan,
QueryGuard averages the time per cost unit over its last 50 or so runs of
5 ms or more, and charges budgets the planned cost times that plan's time per
unit over the server's. The server's is averaged over all such runs, in log
terms and weighted by cost, so a cheap statement that waited long on a lock
barely moves it. A quicker run is mostly the round trip and the work every
statement does, and would make long plans look cheap next to it;
`min_charge` covers it instead. A plan seen only a
few times leans on the server's average instead: its own timing counts for
n / (n + `credibility`) after n runs, as in Bühlmann's credibility formula.
The factor stays between 1/100 and 100, and `max_cost` still judges the
planner's own cost, the number `EXPLAIN` shows.

```json
{"calibration": {"mode": "on", "credibility": 10}}
```

When a timed statement ends, its charge is trued up to what it took: the
time, at the server's average time per cost unit, replaces the estimate, and
the tenant pays the difference or gets it back. A statement that failed or
was cancelled pays for the time it ran too.

`"mode": "off"` charges the planner's cost, with no true-up. The time measured includes the
network round trip and the time the client takes to read the rows. Statements
that share a `Sync`, as in a pipeline or a batch, aren't timed, because
PostgreSQL sends their answers together at the `Sync`. Nor is `DECLARE`, since
its query runs in the `FETCH`es that follow.

### Plan flips

A plan flip is a statement's plan suddenly getting worse, and QueryGuard
catches two kinds:

- A plan that reads a table in full where the statement's usual plan reads
  it through an index, as after an index is dropped. The usual plan is the
  one with the most recent runs, among plans run at least 5 times. A plan
  that has run 5 times while the usual one kept running too is the plan for
  other values, as a common value in skewed data gets, and isn't a flip.
- A run more than 10 times slower than the plan usually takes, and at least
  100 ms, since under load a quick statement now and then takes tens of
  milliseconds. This is how a switch to a generic plan shows: QueryGuard explains a
  prepared statement with its bound values, so its `EXPLAIN` shows the plan
  for those values, not the generic plan PostgreSQL may run instead.

A flipped statement runs in the slow lane, and the flip is logged once
(`msg="plan flip"`). Each plan's past runs fade with `quarantine` as their
half-life, so a new plan that stays in use becomes the usual one after about
that long. After a slow run, the statement is explained again rather than
taken from the plan cache, and DDL, `VACUUM` and `ANALYZE` sent through
QueryGuard clear the database's cached plans once they are committed, so a
dropped index shows before the statement next runs.

```json
{"plan_flips": {"mode": "enforce", "quarantine": "10m"}}
```

`"mode": "warn"` only logs flips; so does a config without a scheduler,
which has no slow lane.

### Stale statistics

With `-catalog-dsn`, a flip's log line also names the tables the plan reads
whose statistics are stale, with the hint to run `ANALYZE`. A table is stale
when more than 50 rows plus 20% of it changed since it was last analyzed
(`n_mod_since_analyze`), twice what makes autovacuum analyze it by default.

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
the query next reads or writes the socket. QueryGuard sends a CancelRequest
for the statement as soon as the client's connection closes, and also sends
`client_connection_check_interval=2000` with each new session, so the query
stops within about 2 seconds even if the proxy itself goes away. A value the
client sets, directly or in `options`, is kept. Change it with `-client-check-interval`; `0` leaves the
server's setting alone, and is needed on platforms where PostgreSQL rejects a
non-zero value.

## Compatibility

`make compat` runs these clients through QueryGuard against a real PostgreSQL
(`PG=16`, `17` or `18`; start the servers with `make up`), and CI runs it on
all three versions:

| Client | Checked |
| --- | --- |
| pgx 5.11 | plaintext, TLS, direct TLS, protocol 3.2, prepared statements, COPY, cancel on 3.0, 3.2 and 3.2 over TLS, keepalive settings; rejections in all three query modes, in a transaction and in a pipeline; warn mode; connection cap; cost rules in all three query modes and in a transaction, errors from `EXPLAIN`, the plan cache, table sizes; budgets that reject and that queue, busy slots, statement and idle-in-transaction timeouts, cancel on disconnect, tenant tags; plan flips from a dropped index and from a forced generic plan, stale statistics |
| psql 18 | plaintext, TLS, direct TLS, protocol 3.2, Ctrl-C; rejection, in a transaction; costly statement |
| node-postgres 8 | plaintext, TLS, parameters, cancel; rejection, in a transaction; costly statement, with and without parameters |
| psycopg 3.3 (libpq 18) | plaintext, TLS, direct TLS, protocol 3.2, parameters, cancel, cancel over TLS; rejection, in a transaction and in a pipeline; costly statement, prepared and not |

Every client also checks that its cancel key is the proxy's own, not the
server's, and that the connection stays usable after a rejection.

## Overhead

`make overhead` times 5,000 runs of each query straight to PostgreSQL and
through QueryGuard: without rules, with the rules from the compatibility
tests, and with the cost rules. Ranges are over three runs on an Apple M1,
with PostgreSQL 18 in Docker (OrbStack) and the proxy in the benchmark's
process:

| Query | Path | p50 | p99 |
| --- | --- | --- | --- |
| `select 1` | direct | 134–140 µs | 269–395 µs |
| `select 1` | QueryGuard | 161–166 µs | 242–285 µs |
| `select 1` | QueryGuard, TLS from the client | 155–161 µs | 241–278 µs |
| `select 1` | QueryGuard with rules | 145–159 µs | 236–261 µs |
| `select 1` | QueryGuard with rules, simple protocol | 173–180 µs | 266–330 µs |
| `select 1` | QueryGuard with cost rules | 158–164 µs | 245–316 µs |
| `select 1` | QueryGuard with cost rules, simple protocol | 178–182 µs | 257–351 µs |
| 1,000 rows (about 50 KB) | direct | 932–933 µs | 1,253–1,263 µs |
| 1,000 rows (about 50 KB) | QueryGuard | 1,032–1,096 µs | 1,321–1,433 µs |
| 1,000 rows (about 50 KB) | QueryGuard, TLS from the client | 1,035–1,074 µs | 1,355–4,754 µs |
| 1,000 rows (about 50 KB) | QueryGuard with rules | 1,029–1,034 µs | 1,319–1,420 µs |
| 1,000 rows (about 50 KB) | QueryGuard with rules, simple protocol | 1,092–1,093 µs | 1,488–1,609 µs |
| 1,000 rows (about 50 KB) | QueryGuard with cost rules | 1,034–1,103 µs | 1,393–1,546 µs |
| 1,000 rows (about 50 KB) | QueryGuard with cost rules, simple protocol | 1,100–1,168 µs | 1,537–1,675 µs |

The proxy adds about 20–30 µs to a round trip at p50, and 10–18% to the
1,000-row result. pgx prepares each statement once, so rules parse it only
then, and the cost check finds its plan in the cache: neither adds anything
measurable. With the simple protocol every run is parsed, which adds up to
about 20 µs for `select 1` and 60 µs for the 1,000-row query; the cost check
adds a few microseconds more, for the fingerprint. Each of these runs
explains a statement only once, so they show the cache's cost, not
`EXPLAIN`'s; the proxy logs the time spent explaining every minute. The
4.8 ms p99 came from one noisy run; the other two were under 1.4 ms. These
are laptop numbers; the full benchmark matrix comes with v1.0.

## A rogue tenant

`make rogue` runs three innocent tenants doing indexed lookups (six
connections) next to a rogue one running full reads of the 10M-row `orders`
table (six connections), for 15 seconds a scenario. Through QueryGuard the
rogue gets a budget of 50,000 cost units a second (a full read is planned at
about 169,000), with 8 slots shared fairly. Apple M1, PostgreSQL 18 in Docker:

| Scenario | Innocent p50 | Innocent p99 | Rogue statements run |
| --- | --- | --- | --- |
| No rogue, straight to PostgreSQL | 0.27 ms | 0.57 ms | |
| No rogue, through QueryGuard | 0.35 ms | 0.74 ms | |
| Rogue, straight to PostgreSQL | 0.44 ms | 4.18 ms | 52 |
| Rogue, QueryGuard, a role per tenant | 0.40 ms | 1.10 ms | 6 (14,044 refused) |
| Rogue, QueryGuard, one shared role and tags | 0.42 ms | 1.06 ms | 6 (13,994 refused) |

Without QueryGuard the rogue raises innocent p99 more than sevenfold. Through
it, innocent p99 stays within 1.5 times the same path's baseline, the target
the test checks, and the rogue runs exactly what its budget allows: 200,000
units of burst plus 15 seconds at 50,000 pay for six full reads. Its full
reads are nearly the only runs long enough to calibrate costs by, so their factor
stays 1, and no innocent lookup was taken for a plan flip. These are laptop
numbers; the full benchmark comes with v1.0.

## License

MIT. See [LICENSE](LICENSE).
