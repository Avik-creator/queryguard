# Interview questions

The questions an interviewer is likely to ask about QueryGuard, with answers
drawn from the code, the [README](../README.md) and the
[benchmark](building-queryguard.md#the-numbers). A good interviewer uses a
project like this to find out whether the builder understands systems design
or only put features together, so each answer also says where the design
stops working.

## Architecture

**Why did you build this as a Postgres proxy instead of an extension?**

An extension needs `shared_preload_libraries`, and managed services such as
RDS, Neon and Supabase don't let you load arbitrary ones. A proxy needs only a
login (and `pg_monitor` for the server-activity features), so it works on any
PostgreSQL 16 to 18 without touching the server. It also fails apart from the
server: a crash in QueryGuard ends its sessions, not the postmaster.

The price is real. An extension sits in the planner and executor, so it sees
the plan that actually runs, the time it actually takes, and the SQL inside
functions and triggers. A proxy sees none of that. It has to run its own
`EXPLAIN`, which costs a round trip on a cache miss; it adds a network hop to
every statement (30–44 µs at p50 in the benchmark); and it can only measure
wall-clock time as the client sees it, not CPU time.

**Where exactly does QueryGuard sit?**

Between the application (or its driver) and PostgreSQL, speaking the wire
protocol on both sides. Each client connection gets its own server
connection; QueryGuard doesn't pool. It terminates the client's TLS, issues
its own cancel keys, and passes authentication through to PostgreSQL, so
PostgreSQL still checks every password. If connections are the problem,
PgBouncer goes behind it.

**What happens if the proxy crashes?**

Its sessions end. PostgreSQL rolls back any open transaction when the server
connection drops, and since QueryGuard sends `client_connection_check_interval=2000`
with each session, a running query stops within about 2 seconds even though
nothing is left to read its result. Clients reconnect through the load
balancer to another instance, and limits shared through `-state-dsn` hold
across the rest. A panic in one session closes only that session; the
process stays up. A planned restart drains instead: with `-reuse-port` the
new process listens on the same address while the old one finishes, and in
the compatibility tests that dropped none of 400 transactions.

What is lost on a crash is what QueryGuard learned: calibration, plan
history, stats, kills and the watch list live in memory. Only the allowlist
is saved to a file.

**Can it be horizontally scaled?**

Yes. Instances in front of the same server share their limits through a small
store (three tables in a database set aside for QueryGuard). Every second each
instance reports what it used and gets a 10-second lease on its share of each
budget and lane, as YouTube's Doorman does. Statements only ever touch the
instance's own copy, so the store is off the hot path. Cancel keys carry the
instance's ID, so a cancel that lands on the wrong instance is forwarded to
the owner.

## Postgres internals

**What does planner cost mean?**

An estimate in arbitrary units, where reading one page in sequence costs
`seq_page_cost` (1.0) and everything else (`random_page_cost`,
`cpu_tuple_cost`, `cpu_operator_cost` and so on) is relative to it. Each plan
node has a startup cost and a total cost; QueryGuard uses the top node's total
cost. It is not time: it doesn't know about cache hits, lock waits, other load
on the server, or how fast the disk is.

**Why use `EXPLAIN`?**

It is the only estimate available before a statement runs, and it comes from
the same planner that will run it. QueryGuard runs `EXPLAIN (FORMAT JSON,
VERBOSE)` on the client's own connection, so the plan sees the same role,
row-level security, `search_path`, temporary tables and settings as the
statement itself. It also tells QueryGuard which tables are read in full,
which `max_scan_rows` and plan-flip detection need.

**How accurate is planner cost compared with actual runtime?**

Accurate enough to rank a primary-key lookup against a full read of a 10M-row
table, which is what matters most here, but not accurate as time. Two plans
of the same cost can differ by orders of magnitude: one reads cached pages in
order, the other scattered pages from disk or waits on a lock. So QueryGuard
calibrates: for each plan it learns time per cost unit over its last 50 or so
runs of at least 5 ms, compares that with the server's average, and charges
the planned cost times that ratio. The ratio is kept between 1/100 and 100.

**How do prepared statements and bound parameters affect the plan?**

Over the extended protocol QueryGuard explains at `Bind`, with the values
being bound, so a selective value gets the index plan and a common value gets
the scan, and each is priced as such. Values over 1 MB aren't sent twice; it
asks for the generic plan instead.

The catch is that PostgreSQL may switch a prepared statement to its generic
plan after five executions (`plan_cache_mode = auto`), and QueryGuard's
`EXPLAIN` with bound values shows the custom plan, not the one that runs. That
can't be seen before the run, so it is caught after: a run more than 10 times
slower than the plan usually takes, and at least 100 ms, is treated as a plan
flip and the statement goes to the slow lane. The compatibility tests force
a generic plan to check this.

**What happens with transactions, locks, RLS, `SET ROLE` and temporary tables?**

- **Transactions:** `BEGIN`, `COMMIT`, `ROLLBACK` and `SAVEPOINT` never wait
  for a budget or a slot, since the slot they'd wait for may be held by a
  statement waiting on the very locks the `COMMIT` would release. A statement
  rejected inside a transaction is replaced by a `DO` block that raises the
  error, so PostgreSQL fails the transaction exactly as it would for any other
  error.
- **Locks:** with server activity on, QueryGuard reads `pg_blocking_pids` once
  a second. Sessions that others wait on get past every limit, so a blocker
  is never stuck behind the statements it blocks. Time spent waiting on another
  tenant's locks is charged to the tenant holding them ("blocker pays"). DDL
  waiting in a lock queue with others behind it is cancelled with `55P03`.
- **RLS and `SET ROLE`:** plans are cached by database, role and statement.
  A session that may switch roles, through `SET ROLE`, `SET SESSION
  AUTHORIZATION` or `set_config`, explains every statement from then on and
  never uses the shared cache, since RLS can give another role a different
  plan for the same text. The tenant, rules and budget stay those of the login
  role.
- **Temporary tables:** `EXPLAIN` runs on the client's own connection, so it
  sees them.

## Scheduling and fairness

**How do you define a tenant budget?**

A token bucket in planner cost units: it fills at `rate` units a second up to
`burst`. A statement may start while its tenant owes nothing, and its
calibrated cost (at least `min_charge`) is then taken, which may push the
bucket below zero. So one large statement is never starved, and the long-run
rate still holds, because the tenant then owes. What happens next is
`when_over`: queue until repaid, run in the slow lane, or reject with `53000`
and a jittered retry hint. A budget can also be a share of measured server
capacity (`capacity: 0.2`) rather than a fixed rate.

**Why not just use connection limits?**

One connection is enough to read a 10M-row table in full. In the benchmark the
rogue tenant had six connections, the same as the innocent ones, and still
pushed their p99 from about 0.6–1 ms to 5–8 ms. Connection limits bound
concurrency, not work. QueryGuard has connection caps too, but budgets are
what tie a tenant to the work it does.

**How do you prevent one tenant from starving others?**

Three layers. The budget limits how much work a tenant does over time. The
slots limit how many statements run at once, and each free slot goes to the
waiting tenant with the least recent use for its `share` (use fades with a
10-second half-life), so a heavy tenant goes to the back. Priorities sit above
both: `critical` first, and `best_effort` is shed first when the server is
overloaded. In the benchmark the rogue ran 5–8 full reads instead of 23–45 and
was refused 10,800–13,800 times.

**What scheduling algorithm do you use?**

A token bucket per tenant for admission, then a slot scheduler that orders
waiters by priority, then by recent use divided by share (an approximation of
weighted fair queueing, as CockroachDB's admission control does it), then by
arrival. Arrival is first-in, first-out normally. Once the queue has stayed
non-empty for a second, it switches to Facebook's adaptive LIFO with CoDel:
newest first, since that client is likeliest to still be waiting, and
statements that waited over 500 ms are turned away. The number of fast-lane
slots moves by AIMD, as TCP's congestion control does: it backs off by 10%
when statements run more than twice their usual time or a quarter of the slots
wait on locks, and grows by one when every slot was in use during a calm
second.

**How do you handle bursty workloads?**

`burst` lets a quiet tenant spend ahead. Going below zero lets one big
statement through without starving it. Queue timeouts and deadlines turn a
statement away early rather than late, and the retry hint adds up to half
again at random so a crowd turned away together doesn't return together. If a
burst becomes a standing queue, adaptive LIFO keeps latency for new work
bounded instead of serving clients that have already given up.

## Performance

**What latency overhead does the proxy add?**

From `make bench` (PostgreSQL 16, 17 and 18, three runs each, Apple M1 laptop):
30–44 µs at p50 on `select 1`, and 127–156 µs, about 12%, on a 1,000-row
result. Rules add under 10 µs, the cost check with a cached plan up to about
20 µs more, and the simple protocol 10–40 µs more, since every run is parsed
and fingerprinted. Most of it is the extra hop: every round trip crosses two
connections instead of one, and QueryGuard reads each message before passing
it on.

**Does every query require an `EXPLAIN`?**

No. Only when cost rules, budgets or slots are configured, and only for a query
string holding one `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `MERGE`, `DECLARE`
or `CREATE TABLE AS`. Transaction control and multi-statement strings are
charged `min_charge` without one. Plans are cached, and the budget is checked
before `EXPLAIN`, so a tenant that is already over budget doesn't even cost
an `EXPLAIN`.

**How do you cache query plans?**

For a minute, keyed by database, role and statement. When a cost rule that
blocks applies, the key includes the bound values, since a selective value
and a common one get very different plans. Budgets and warn-mode rules share
one plan across values, keyed by the fingerprint, and re-explain about one hit
in 100 to notice drift. DDL, `VACUUM` and `ANALYZE` sent through QueryGuard
clear the database's cached plans once committed, and a slow run makes the
statement be explained again next time.

**What happens for a 1 ms OLTP query, where proxy overhead is significant?**

At 30–44 µs the hop is 3–4% of a 1 ms query, and for a 125 µs `select 1` it is
about a third. With a cached plan the cost check adds up to about 20 µs more. A
cache miss costs an `EXPLAIN` round trip plus planning time, which the
benchmark doesn't isolate (each run explains a statement once, so it measures
the cache, not `EXPLAIN`); in production QueryGuard logs the cache hit rate and
time spent explaining every minute, and exports
`queryguard_explain_seconds_total`. For a workload that is only sub-millisecond
lookups from one well-behaved tenant, the honest answer is that QueryGuard is
pure cost. Its value shows on the day someone misbehaves.

**What are your p50, p95 and p99 numbers?**

The benchmark reports p50 and p99, not p95. Overhead is above. Next to a rogue
tenant, innocent p99 was 1.1–3.5 ms through QueryGuard against 4.7–8.1 ms
straight to PostgreSQL, with baselines of 0.5–1.1 ms straight and 0.8–1.5 ms
through QueryGuard. Four of nine runs missed the test's own target (1.5 times
the baseline plus 1 ms) by 0.1–0.8 ms: QueryGuard decides how often the rogue
reads, not how heavy each admitted read is, and the lookups that land during
one are the slowest 1%. These are laptop numbers with PostgreSQL in a VM. The
query stats keep p50, p95 and p99 per statement and tenant at run time.

## Correctness and edge cases

**What if the query plan changes after you approve it?**

The window is small, since `EXPLAIN` runs at `Bind`, just before `Execute`. It
still exists: a generic plan, a concurrent `ANALYZE`, or a cached plan from the
last minute. QueryGuard handles it after the fact. The charge is trued up from
how long the statement actually took, and a run that reads a table in full
where the usual plan used an index, or takes over 10 times its usual time,
is a plan flip: logged once, sent to the slow lane, and explained again next
time instead of read from the cache.

**What if statistics are stale?**

Then the estimate is wrong, and the defences are the same as for any bad
estimate: the true-up charges the real time, calibration learns that plan's
real time per cost unit, and the timeout caps the damage. With `-catalog-dsn`,
a plan flip's log line names the tables whose statistics are stale (more than
50 rows plus 20% changed since the last `ANALYZE`) with the hint to run it.
QueryGuard doesn't run `ANALYZE` itself.

**What if `EXPLAIN` says a query is cheap but it becomes expensive at runtime?**

It is admitted, since it looked cheap, and takes one slot. From there:

- the tenant's `statement_timeout` cancels it, or with `learned_timeouts` a
  multiple of that statement's own p99, so a 20 ms statement can't run for
  30 s;
- with `demote_after` set (say 10 s), from then on it counts against the slow
  lane and its fast slot goes to the next statement;
- when it ends, its charge is trued up to its real time and the tenant owes
  the difference, so its next statements wait;
- if it broke a timeout or a row cap, its fingerprint goes on a watch list,
  and its next runs can be logged, slowed or rejected for 10 minutes.

**How do you handle `COPY`, cancellation, pipelining and protocol errors?**

- **COPY:** relayed, and `COPY (query) TO` is judged by its query's plan. One
  of the audit's bugs was here: libpq sends `Sync` for `COPY … FROM STDIN`
  over the extended protocol, then the data, then another `Sync`, and
  PostgreSQL ignores the first. The proxy expected two answers, got one, and
  the session never looked idle again, so its slot leaked.
- **Cancellation:** clients get proxy-issued cancel keys, not the server's.
  QueryGuard maps them back, forwards cancels across instances, and cancels a
  statement itself when its client disconnects.
- **Pipelining:** a session holds one slot until PostgreSQL has answered
  everything it sent. A statement rejected in a pipeline is raised inside
  PostgreSQL, so the pipeline's earlier statements roll back as after any
  other error. Statements sharing a `Sync` aren't timed, since their answers
  arrive together.
- **Protocol errors:** the startup negotiation is fuzzed, a fast-path
  `FunctionCall` (which names its function only by OID) is treated as
  unreadable and refused by default, and a panic ends only its own session.

## Distributed systems

**If you run three QueryGuard replicas, how do they share tenant budgets?**

Each holds its own copy of each budget and lane, sized by a lease from the
store. Every second it reports what it spent and whether it was starved, and
gets back what it asked for plus an even part of what is spare, or, when
instances together ask for more than there is, a part in proportion to what
each asks. Slots are leased in whole numbers, so with fewer slots than
instances some hold one and others none, instead of every instance rounding
down to zero.

**How do you avoid race conditions?**

Within an instance, the budget check and the charge happen under one lock
(`Spend`), so statements arriving together can't spend the same tokens. A
cheaper check without a charge (`Reserve`) runs before `EXPLAIN`, so an
over-budget tenant doesn't cost one. Across instances, the store hands out
shares one instance at a time under an advisory lock, and only what the others
can't be using, so the shares never add up to more than the limit. A smaller
lease doesn't stop statements already running, so the store keeps counting
slots an instance reports in use until they end.

**What happens if the shared state store is unavailable?**

Each instance keeps running on as much of its last share as fits
`1/max-instances` of the limit, which the store keeps aside for it, for a
minute after its last lease. Then it stops admitting statements that count
against a shared limit until the store is back. Losing the store or an
instance never admits more than the total. The store's tables are ordinary
logged tables, since losing them in a crash would let the store hand out again
what instances still hold.

**Do you favour availability or strict enforcement?**

It depends on what failed, and that is deliberate:

- **Shared limits:** strict. After the minute of grace, statements against a
  shared limit stop rather than over-admit, because over-admitting is the
  failure QueryGuard exists to prevent.
- **Estimates:** available. If `EXPLAIN` fails, the statement goes to
  PostgreSQL, which reports its own error if there is one. A statement is never
  refused because it couldn't be planned.
- **Server activity:** after three failed readings, QueryGuard acts as if the
  server were idle, so a hold or cap can't outlast the data it came from.
- **SQL it can't parse:** strict by default (`unchecked: reject`), since
  otherwise any rule can be sidestepped by writing SQL the parser can't read.

## Security

**Can this safely sandbox arbitrary SQL?**

No, and the README says so: QueryGuard is not a security boundary on its own.
It reads SQL with PostgreSQL's own parser, which removes the class of bugs
where the proxy reads a statement differently from the server, but functions,
views and triggers run SQL it never sees. It catches mistakes and keeps tenants
within their share; privileges belong in PostgreSQL.

**Can a function hide a dangerous operation?**

Yes. `deny_functions` sees only calls written in the statement. A function
that calls another, `EXECUTE` of text built at run time, a trigger, or
`select o.purge_order from orders o` (a one-argument function called as if it
were a column) are all out of its sight. The fix is in PostgreSQL: revoke
`EXECUTE` on the function.

**Why isn't this a security boundary?**

Because enforcement in front of the server can only see the text. The server
can run code the text doesn't show, and the server's settings can change how
text is read: with `standard_conforming_strings` off or a non-UTF-8 client
encoding, PostgreSQL may read a string differently from the parser, so
QueryGuard refuses such statements rather than guess. A boundary has to sit
where the work is done, and that is PostgreSQL's privilege system.

**How do you stop SQL injection?**

QueryGuard doesn't, and shouldn't claim to; parameterized queries in the
application do. Two features limit the damage of one. The learned allowlist,
for roles that should run only a known set of statements, refuses any
statement whose fingerprint it hasn't learned, and an injection such as
`' OR '1'='1` or a `UNION` changes the parse tree and so the fingerprint.
Rules such as `require_where` and `deny_ddl`, and a read-only role, make an
injected statement less able to do harm. Neither replaces fixing the
application.

**What can Postgres permissions do that QueryGuard cannot?**

Enforce inside the server, on everything: functions, triggers, views,
`EXECUTE` of dynamic SQL, and every connection, including those that don't go
through QueryGuard. `GRANT` and `REVOKE`, row-level security, read-only roles
(`pg_read_all_data`, `default_transaction_read_only`) and revoking `EXECUTE`
can't be sidestepped by clever SQL. That is why the AI-agent preset tells you to
give the agent a read-only role as well.

## Product judgment

**Who actually needs this?**

Teams with several tenants, services or AI agents on one PostgreSQL server,
where one of them can hurt the rest: multi-tenant SaaS on a shared database, a
reporting tool next to the OLTP workload, an AI agent behind a Postgres MCP
server. It matters most on managed PostgreSQL, where the extension-based
alternatives can't be installed.

**Why wouldn't customers just use PgBouncer?**

PgBouncer limits connections, and connections aren't work. It has no idea what
a statement costs, so it can't tell a primary-key lookup from a full read. They
solve different problems and combine: QueryGuard in front for admission,
PgBouncer behind it when the server has too many connections. QueryGuard's
admin console and cancel forwarding follow PgBouncer's. The combination with
transaction pooling is untested; QueryGuard explains on the client's own
connection, and with transaction pooling an `EXPLAIN` outside a transaction
could reach a different server connection from the statement.

**How is this different from RDS resource management?**

The managed controls I know of work at the level of the instance or the
connection: instance size, connection limits, and settings such as
`statement_timeout` in a parameter group. None of them knows which tenant a
statement belongs to or what it will cost before it runs, and they don't
allow loading cost-limiting extensions such as pg_plan_filter. QueryGuard
adds decisions per statement, per tenant, by planned and calibrated cost.

**What's the strongest use case?**

A shared PostgreSQL where one tenant's expensive queries hurt everyone's
latency, measured in the benchmark: innocent p99 at 1.1–3.5 ms instead of
5–8 ms next to a tenant reading a 10M-row table in full. The second is AI
agents: the preset refuses all 66 known read-only bypasses in its corpus
while allowing its 12 ordinary reads, limits cost, rows and time, and learns
an allowlist.

**What would stop a company from putting this in production?**

- It is in the path of every statement, so it must be run as a fleet with a
  store, and that is more to operate.
- 30–44 µs at p50 is pure cost for a workload no one misbehaves in.
- What it learns lives in memory and starts over after a restart.
- It has one maintainer, and it was benchmarked on a laptop, not production
  hardware; the rogue test missed its target in 4 of 9 runs.
- It doesn't pool, isn't a security boundary, and streaming replication
  through it is untested.

## Going deeper on one decision

After the buckets, an interviewer usually picks one decision and keeps pulling
on it. If the answer is "we use `EXPLAIN` to estimate cost", the chain goes:

**1. "Planner cost isn't milliseconds. How did you calibrate it?"**

Per plan, QueryGuard times each run from when the statement goes to
PostgreSQL until it is answered, and keeps the time per cost unit over the
last 50 or so runs of at least 5 ms (quicker runs are mostly round trip;
`min_charge` covers them). Each tenant's runs are averaged in log terms and
weighted by cost, so a cheap statement that waited on a lock barely moves it.
The server's rate is the mean of the tenants' averages, each counting for its
runs up to 100, times its mean cost. A statement is charged its planned cost
times its plan's rate over the server's. A plan seen only a few times leans on
the server's rate instead: its own timing counts for n / (n + credibility)
after n runs, as in Bühlmann's credibility formula.

The weighting has a story. The audit found that a plan of a disabled plan type,
which PostgreSQL before 18 prices 10 billion units higher, would set the
server's average for everyone. The first fix capped each tenant's weight at a
mean cost of 1000. The benchmark then showed the rogue running twice as many
full reads: hundreds of innocent lookups, slowed by waiting behind the rogue
and now weighing nearly as much as a full read, pulled the server's time per
unit up, so a full read looked cheap beside it. The cap was replaced by
leaving such plans out of the average, with a test that holds four tenants'
waiting lookups next to a full read.

**2. "What happens if table statistics are stale?"**

The plan and its cost are wrong. Calibration absorbs a steady error, since
it learns that plan's real time per unit. A sudden one shows as a plan flip,
whose log line names the stale tables. Either way the charge is trued up from
the real time when the statement ends.

**3. "What if the estimated cost is 1,000 and execution takes 30 seconds?"**

It is admitted at its calibrated estimate and holds one slot. The timeout
cancels it (with learned timeouts, long before 30 seconds if it usually takes
milliseconds); `demote_after`, if set, moves it to the slow lane's count; at the end its charge is trued up to 30 seconds' worth of cost units
at the server's rate, so the tenant goes deep into debt and its next statements
wait; the plan's calibration ratio rises, so the next run is charged more up
front; and if it was cancelled, its fingerprint goes on the runaway watch list.

**4. "Do you charge the estimated cost or the actual cost?"**

Both, in turn. The estimate is charged at admission, because the decision has
to be made before the statement runs. When it ends, the charge is trued up:
its time at the server's average time per cost unit replaces the estimate,
and the tenant pays the difference or gets it back. A statement that failed or
was cancelled pays for the time it ran. Rows returned (128 units a MB) and
usual WAL written (128 units a MB, from `pg_stat_statements`) are charged on
top, since `EXPLAIN` doesn't show them.

**5. "What happens to fairness while the long query is still running?"**

This is the weak spot, and it is worth saying so. While it runs, its tenant
has paid only the estimate, so its budget and its recent use look as if the
statement were cheap. Its other statements can still be admitted until the
true-up lands at the end. What bounds the damage meanwhile is the slot it
holds (one, and with `demote_after` a slow-lane one), the timeout, and the
adaptive limit, which backs off when statements run longer than usual so other
work gets fewer slots for it to slow down. Charging running statements as they
go, every second rather than at the end, would close the gap; it isn't built.

## Walk through one query

> "Walk me through exactly what happens from the moment a client sends
> `SELECT * FROM events WHERE tenant_id = $1` until the client receives rows."

With pgx's extended protocol, budgets, slots and a cost rule configured:

1. **Login, once per session.** QueryGuard negotiates TLS, relays the startup
   message and authentication to PostgreSQL, and gives the client its own
   cancel key. The tenant is the login role. Connection caps and the
   failed-login throttle apply here.
2. **`Parse`.** QueryGuard parses the SQL with libpg_query and fingerprints
   it (constants ignored). Rules run now: `deny_ddl`, `schema_allowlist`,
   `deny_functions`, the allowlist and so on, on every statement in the text,
   including those inside CTEs. A `/*tenant='acme'*/` tag from a trusted role
   names the tenant. A rejection is answered with `42501`.
3. **About to execute, at `Bind`.** The kill switch and runaway watch list
   are checked. `Reserve`
   checks the tenant owes nothing, without charging, so an over-budget tenant
   doesn't cost an `EXPLAIN`.
4. **Plan.** QueryGuard looks up the plan cache by database, role and
   fingerprint (and the bound values, if a blocking cost rule applies). On a
   miss it runs `EXPLAIN (FORMAT JSON, VERBOSE)` with the bound value on the
   client's own connection.
5. **Price.** Cost rules (`max_cost`, `max_scan_rows`) judge the planner's own
   cost; a block is `54000`. For the budget, the cost is calibrated by the
   plan's time per unit and plan-flip detection checks it against the
   statement's usual plan.
6. **Admit.** `Spend` checks and charges the tenant in one step, under one
   lock. Over budget, `when_over` queues it, sends it to the slow lane or
   rejects it with `53000`. Then `Acquire` waits for a slot, ordered by
   priority, then recent use for share, then arrival. A statement whose
   deadline can't be met is answered `57014` without being run.
7. **Execute.** The messages go to PostgreSQL. Timers watch the statement
   timeout; rows and bytes are counted against the row and byte caps; a
   client that disconnects has its statement cancelled.
8. **Rows.** Rows stream back through the proxy as they arrive.
9. **Settle.** At `ReadyForQuery`, the slot is released. The time taken trues
   up the charge, the bytes returned are surcharged, the plan's timing feeds
   calibration and its history, and the statement goes onto a bounded queue
   for the query stats, the anomaly detector and the traffic log, so a slow
   consumer drops records rather than slowing the session.

## The three that matter most

**1. Why a wire-protocol proxy rather than a Postgres extension?**

See [Architecture](#architecture). In short: it runs on managed PostgreSQL
and fails apart from the server, at the price of a hop, its own `EXPLAIN`,
wall-clock rather than CPU time, and no sight inside functions.

**2. How does your scheduler guarantee fairness without destroying latency?**

It doesn't guarantee it, it bounds it, and the benchmark shows by how much.
Fairness comes from pricing statements before they run, so an expensive
tenant runs out of budget instead of slots, and from giving each free slot to
the tenant that has used least lately. Latency is protected by keeping the
expensive checks off the cheap path: the budget is checked before `EXPLAIN`,
plans are cached, transaction control never waits, and statements whose client
will have given up are refused at once. Under overload the queue turns LIFO
with a short timeout, the slot limit backs off by AIMD, and best-effort work is
shed first. The limit is what was admitted: QueryGuard decides how often the
rogue reads, not how heavy each read is, which is why 4 of 9 runs missed the
p99 target by under a millisecond.

**3. Tell me about the hardest correctness bug or race condition you hit.**

A cancel that hit the wrong statement. When QueryGuard cancels a statement
itself, for a timeout or a row cap, it opens a new connection and sends
PostgreSQL a `CancelRequest`. That is asynchronous: PostgreSQL signals the
backend some time later, and the protocol gives no reply. If the client sent
its next statement in the meantime, the signal could land on that one, and
an innocent statement failed with "canceling statement". The fix was to read
the cancel connection until PostgreSQL closes it, which it does only after
signalling the backend, and to hold the client's next message until then.

Two others are worth having ready:

- **A deadlock the scheduler made.** A transaction updates a row and goes
  idle, freeing its slot. Another session takes the last slot and waits on
  that row. The first transaction's next statement now waits for a slot only
  it can free. The fix: transaction control never waits for a slot, and
  sessions that others wait on (from `pg_blocking_pids`) bypass every limit,
  while still paying for it later.
- **The calibration fix that doubled the rogue's reads**, described in
  [the chain above](#going-deeper-on-one-decision). The lesson was that a fix
  needs the test that guards what it might break, not only the one that found
  the bug.

## What was deliberately left out

- **Pooling.** PgBouncer does it well; QueryGuard goes in front of it.
- **Being a security boundary.** PostgreSQL's privileges are the boundary;
  QueryGuard catches mistakes and keeps tenants within their share.
- **Persistence of what it learns.** Calibration and stats rebuild in minutes
  and would need a store on the hot path to persist; only the allowlist is
  saved.
- **Costing multi-statement strings.** `EXPLAIN` plans one statement at a
  time and a later one may need what an earlier one creates, so under a cost
  rule they are refused, with a request to send them one at a time.
- **Rewriting queries, or caching results.** It admits, delays or refuses;
  it never changes what a statement means.

## Where the architecture breaks down

- Work inside functions, triggers and dynamic SQL is invisible to it.
- A running statement is charged only its estimate until it ends.
- It measures wall-clock time as the client sees it, including the network
  and how fast the client reads rows, not CPU or I/O.
- The plan it judges may not be the one that runs (generic plans), which is
  caught only after a slow run.
- `EXPLAIN` has no time limit of its own yet, so a statement with slow
  planning pays for it twice.
- In a fleet, kills, the watch list and stats are per instance.
- Replication connections are relayed but untested; PostgreSQL 19 is
  experimental.
