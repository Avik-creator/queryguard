# Building QueryGuard: admission control for a shared PostgreSQL

QueryGuard is a proxy that prices every statement before it runs and gives
each tenant a budget, so one tenant's expensive queries can't starve the
rest of a shared PostgreSQL server. This post is about how it decides, what
broke on the way to v1.0, and what the numbers say.

## The problem

Many teams put tenants, services or AI agents on one PostgreSQL server. The
server has no notion of fairness between them: a report that reads a 10M-row
table in full gets the same CPU, I/O and buffer cache as a lookup by primary
key, and while it runs everyone else's lookups wait. Connection limits don't
help, since one connection is enough to read a table in full. Statement
timeouts help only after the damage is done.

Extensions that limit cost exist, but they need `shared_preload_libraries`,
which managed services such as RDS, Neon and Supabase don't allow. A proxy
needs only a login.

## How a statement is judged

Every statement goes through five steps on its way to PostgreSQL:

1. **Parse** it with PostgreSQL's own parser (libpg_query), so rules see
   exactly what the server will run: a `DROP` inside a CTE, a `COMMIT;` that
   ends a read-only transaction, a write hidden in a function call.
2. **Explain** it on the client's own connection, just before it runs. Over
   the extended protocol that happens at `Bind`, with the values being bound,
   so a lookup on a selective value and a scan on an unselective one get
   different plans. Plans are cached, keyed by those values when a cost rule
   could block.
3. **Calibrate** the planner's cost. Cost units don't map to the same time
   for every plan, so QueryGuard learns, per plan, how long a cost unit takes
   compared with the server as a whole, and charges budgets the corrected
   cost. The server's own rate weighs each tenant by its runs, so one busy
   tenant can't drag everyone's charges toward its own.
4. **Admit** it: take the cost from the tenant's token bucket (burst plus a
   rate), then queue for a slot. Slots are shared fairly, the tenant with the
   least recent use first. An AIMD loop shrinks the number of slots when
   statements slow down or lock waits rise, and best-effort tenants are shed
   first.
5. **Watch** it run: cancel it at its timeout or row cap, true up its charge
   from how long it actually took, and flag a plan that suddenly runs far
   slower than its usual one, sending it to a slow lane.

Each tenant is a role, or a tag such as `/* tenant='acme' */` from a trusted
role, so one shared application role can still carry many tenants.

## What real load found

Unit tests and a fake Postgres carried most of the work. Before v1.0 every
claim was checked again against real PostgreSQL 16 to 19, under real load.
Three of the seven checks found bugs.

- **A lock pile-up raised two anomalies.** Latency and errors both crossed
  their baselines, a minute apart, and each raised its own. Now one incident
  is one anomaly holding every signal that rose, naming the statements that
  were blocked rather than every statement that ran.
- **The adaptive limit recovered while overload went on.** It compared each
  statement's time with the plan's usual time over its last 50 runs, and
  under steady overload 50 slow runs become usual within seconds. The
  baseline now moves over about ten minutes, so the limit stays at its floor
  until the overload ends.
- **The cap on a tenant pinning the MVCC horizon flapped.** The cap ended the
  moment the old snapshot did, and the next one restarted it each second.
  It now holds until the horizon has been clear for twice its limit.

## What an audit found

With the features done, four reviewers read the whole code base, each
taking one layer, and reported 34 issues. Each was checked against the code
before anything changed, and every fix began with a test that failed. A few
are worth telling, because each is a corner of PostgreSQL that is easy to
miss.

- **The fast path.** The protocol has a message, `FunctionCall`, that calls
  a function by its OID with no SQL at all. libpq's large-object functions
  use it. It went straight through every check. Now it is treated as a
  statement QueryGuard can't read, refused unless `unchecked` is `allow`.
- **COPY over the extended protocol.** libpq sends `Parse`, `Bind`,
  `Execute` and `Sync` for `COPY … FROM STDIN`, then the data, then another
  `Sync`. PostgreSQL ignores a `Sync` that arrives while it takes COPY data,
  so it answers once where the proxy expected twice, and the session never
  looked idle again: its slot stayed taken and its idle timer never started.
- **Work no one plan covers.** Cost rules judged one plannable statement.
  `select 1; <huge join>`, `EXPLAIN ANALYZE <huge join>`, `COPY (<query>) TO
  STDOUT` and `EXECUTE` of a prepared statement all ran unjudged. Now the
  plan judged is that of the statement doing the work, and several
  statements that each do work are refused, since `EXPLAIN` plans one at a
  time.
- **TCP_USER_TIMEOUT.** QueryGuard set it to 30 seconds so a dead peer with
  data in flight is found quickly. Since Linux 5.11 it also cuts off a live
  client whose receive window stays shut that long, as one that pauses while
  reading a large result does. Keepalive alone now finds dead idle peers, and
  the kernel's retransmission limit the rest.
- **A cancel that came home.** In a rolling restart the old and new process
  share an address. A cancel for one of the old process's sessions reached
  the new one, which forwarded it to the owner's address, which was its own.

## A fix that made things worse

The benchmark ran again after the audit, and through QueryGuard the rogue
ran twice as many full reads as before. One of the audit's fixes caused it.

QueryGuard calibrates each plan against the server's time per cost unit, an
average over tenants weighted by their mean cost. The audit had found that a
plan of a disabled plan type, which PostgreSQL before 18 prices at 10 billion
units more, would set that average for everyone, so the fix capped each
tenant's weight at a mean cost of 1000. But next to a rogue, every innocent
lookup waits its turn, and hundreds of them, each now weighing nearly as
much as a full read, pulled the server's time per unit up. A full read then
looked cheap beside it and was charged about half.

The cap is gone. A plan whose cost carries the 10 billion is left out of the
server's average instead, the one case the cap was meant for, and a test now
holds the server's timing to the full read's with four tenants' waiting
lookups beside it. Run again, the rogue was back to 5 to 8 full reads a
run, against 7 to 8 before the audit and 8 to 21 with the cap.

The lesson is an old one: a fix needs the same test that found the bug and
the tests that guard what it might break. The unit tests had a rogue and one
waiting lookup; the benchmark had a rogue and three busy tenants.

## The numbers

Everything here is from `make bench`: three runs on each of PostgreSQL 16,
17 and 18, with the versions taking turns within each run so that a machine
growing warmer or busier doesn't favour the first. It ran on an Apple M1,
with PostgreSQL in Docker (OrbStack) and the proxy in the benchmark's
process, so these are laptop numbers: the shape matters more than the
microseconds.

### What the proxy costs

Each query runs 5,000 times, straight to PostgreSQL and through QueryGuard:
without rules, with TLS from the client, with rules, and with cost rules,
over pgx's default extended protocol and over the simple one. The tables
show the median p50 and p99 of the three runs.

`select 1`, p50 / p99 in µs:

| Path | PostgreSQL 16 | PostgreSQL 17 | PostgreSQL 18 |
| --- | --- | --- | --- |
| direct | 126 / 202 | 128 / 207 | 124 / 193 |
| QueryGuard | 161 / 207 | 158 / 294 | 167 / 416 |
| QueryGuard, TLS from the client | 159 / 208 | 173 / 279 | 169 / 240 |
| QueryGuard with rules | 168 / 218 | 159 / 230 | 169 / 258 |
| QueryGuard with rules, simple protocol | 180 / 265 | 186 / 348 | 198 / 310 |
| QueryGuard with cost rules | 171 / 352 | 181 / 371 | 174 / 371 |
| QueryGuard with cost rules, simple protocol | 184 / 352 | 191 / 371 | 214 / 526 |

1,000 rows (about 50 KB), p50 / p99 in µs:

| Path | PostgreSQL 16 | PostgreSQL 17 | PostgreSQL 18 |
| --- | --- | --- | --- |
| direct | 1,096 / 1,319 | 1,077 / 1,668 | 1,128 / 1,546 |
| QueryGuard | 1,223 / 1,471 | 1,215 / 1,525 | 1,284 / 1,725 |
| QueryGuard, TLS from the client | 1,228 / 1,470 | 1,206 / 1,399 | 1,292 / 1,825 |
| QueryGuard with rules | 1,234 / 1,642 | 1,204 / 1,414 | 1,304 / 1,964 |
| QueryGuard with rules, simple protocol | 1,301 / 1,731 | 1,241 / 1,584 | 1,346 / 2,063 |
| QueryGuard with cost rules | 1,274 / 2,010 | 1,250 / 1,803 | 1,361 / 2,044 |
| QueryGuard with cost rules, simple protocol | 1,390 / 2,956 | 1,284 / 1,679 | 1,408 / 2,081 |

The proxy adds 30–44 µs to a round trip at p50, and 127–156 µs, about
12%, to the 1,000-row result. Rules add under 10 µs and the cost check up
to about 20 µs more. p99 moves far more from run to run than p50 does: on a
laptop a few hundred microseconds at p99 is often another process, so a
single p99 cell says less than the three runs behind it.

pgx prepares each statement once, so rules parse it only then, and the cost
check finds its plan in the cache. Over the simple protocol every run is
parsed and fingerprinted, which is where the extra microseconds go.

### What a rogue tenant costs everyone else

Three innocent tenants run indexed lookups on six connections, next to a
rogue running full reads of the 10M-row `orders` table on six more, for 15
seconds a scenario. Through QueryGuard the rogue has a budget of 50,000 cost
units a second, with 200,000 of burst, against a full read planned at about
169,000, and 8 slots shared fairly. The test passes when innocent p99
through QueryGuard stays within 1.5 times the same path's baseline, plus a
millisecond of slack.

Innocent p99 in ms, as the range over three runs, with the rogue's
completed full reads in brackets:

| Scenario | PostgreSQL 16 | PostgreSQL 17 | PostgreSQL 18 |
| --- | --- | --- | --- |
| Baseline, straight to Postgres | 0.54–0.98 | 0.61–0.91 | 0.75–1.05 |
| Baseline, QueryGuard | 0.84–1.26 | 1.02–1.19 | 1.08–1.46 |
| Rogue, straight to Postgres | 4.69–7.10 (23–45) | 5.33–8.08 (23–33) | 5.83–6.29 (26) |
| Rogue, QueryGuard, a role per tenant | 1.14–2.30 (7) | 2.07–3.53 (7) | 2.40–2.52 (8) |
| Rogue, QueryGuard, shared role and tags | 1.15–3.23 (8) | 2.30–2.89 (5–8) | 1.63–2.53 (8) |

Without QueryGuard the rogue runs 23 to 45 full reads and raises innocent
p99 to 5–8 ms, six to ten times its baseline. Through QueryGuard it runs 5
to 8, is refused 10,800 to 13,800 times, and innocent p99 stays at 1.1–3.5
ms. Its budget, 200,000 units of burst plus 15 seconds at 50,000, pays for
about five and a half reads at their planned cost; each charge is then
trued up from how long the read took, so the count moves a little with the
machine.

Four of the nine runs missed the test's target in one scenario: PostgreSQL
16 in one run of three, 17 in all three, 18 in none, by 0.1 to 0.8 ms.
Those misses are not the rogue getting past its budget, since it ran 5 to 8
reads in them as in the runs that passed. QueryGuard decides how often the
rogue reads, not how heavy each read is: an admitted full read still takes
the CPU and disk while it runs, and the lookups that arrive during it are
the slowest 1%, which is what p99 measures. With PostgreSQL in a VM on a
laptop, a scenario this close to its limit passes in one run and misses in
the next; in PostgreSQL 17's first run one scenario passed at 2.29 ms and
the other missed at 2.69 ms. Which version misses most also moves between
benches: before the audit's fixes it was 18, in all three runs, and 17 in
two.

### Reading the raw output

`make bench` writes two files per version and run into `bench/`:

- `bench/overhead-pg<N>-<run>.txt` holds one `BenchmarkOverhead/<query>/<path>`
  line per query and path; its `p50-µs` and `p99-µs` columns are the overhead
  tables.
- `bench/rogue-pg<N>-<run>.txt` holds one `overhead_test.go` line per
  scenario, with `innocent p50`, `p99`, and `rogue ran N, refused M`: the
  rogue table. A run that missed the 1.5 times target ends in
  `--- FAIL: TestRogueTenant`, with the scenario and its limit just above.

## Try it

```sh
make up       # PostgreSQL 16-19 in Docker, with a 10M-row table
make bench    # the numbers above, into bench/ (about 20 minutes)
```

The README covers the rest: the rules, budgets, the admin console, the
AI-agent preset and its bypass corpus, the failure model, and what QueryGuard
can't see. Related work, and what it borrows from whom, is in
[related-work.md](related-work.md).
