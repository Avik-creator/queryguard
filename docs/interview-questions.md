# Interview questions

The questions an interviewer is likely to ask about QueryGuard. A good interviewer uses a project like this to find out whether the builder understands systems design or only put features together.

## The buckets

- **Architecture:** "Why did you build this as a Postgres proxy instead of an extension?", "Where exactly does QueryGuard sit?", "What happens if the proxy crashes?", "Can it be horizontally scaled?"
- **Postgres internals:** "What does planner cost mean?", "Why use `EXPLAIN`?", "How accurate is planner cost compared to actual runtime?", "How do prepared statements and bound parameters affect the plan?", "What happens with transactions, locks, RLS, `SET ROLE`, temp tables?"
- **Scheduling and fairness:** "How do you define a tenant budget?", "Why not just use connection limits?", "How do you prevent one tenant from starving others?", "What scheduling algorithm do you use?", "How do you handle bursty workloads?"
- **Performance:** "What latency overhead does the proxy add?", "Does every query require an `EXPLAIN`?", "How do you cache query plans?", "What happens for a 1 ms OLTP query where proxy overhead is significant?", "What are your p50/p95/p99 numbers?"
- **Correctness and edge cases:** "What if the query plan changes after you approve it?", "What if statistics are stale?", "What happens if `EXPLAIN` says a query is cheap but it becomes expensive at runtime?", "How do you handle `COPY`, cancellation, pipelining, protocol errors?"
- **Distributed systems:** "If you run three QueryGuard replicas, how do they share tenant budgets?", "How do you avoid race conditions?", "What happens if the shared state store is unavailable?", "Do you favor availability or strict enforcement?"
- **Security:** "Can this safely sandbox arbitrary SQL?", "Can a function hide a dangerous operation?", "Why isn't this a security boundary?", "How do you stop SQL injection?", "What can Postgres permissions do that QueryGuard cannot?"
- **Product judgment:** "Who actually needs this?", "Why wouldn't customers just use PgBouncer?", "How is this different from RDS resource management?", "What's the strongest use case?", "What would stop a company from putting this in production?"

## Going deeper on one decision

After the buckets, an interviewer usually picks one design decision and keeps pulling on it. If the answer is "we use `EXPLAIN` to estimate cost", the chain goes:

1. "Planner cost isn't milliseconds. How did you calibrate it?"
2. "What happens if table statistics are stale?"
3. "What if the estimated cost is 1,000 and execution takes 30 seconds?"
4. "Do you charge the estimated cost or the actual cost?"
5. "What happens to fairness while the long query is still running?"

That chain is where real depth shows.

## Walk through one query

> "Walk me through exactly what happens from the moment a client sends `SELECT * FROM events WHERE tenant_id = $1` until the client receives rows."

A strong answer covers each step:

```text
client sends query
      ↓
Postgres protocol parsing
      ↓
identify tenant
      ↓
fingerprint/query lookup
      ↓
possibly EXPLAIN with bound params
      ↓
estimate resource cost
      ↓
check tenant budget/concurrency
      ↓
run / queue / reject
      ↓
execute query on Postgres
      ↓
observe actual runtime/rows/etc.
      ↓
update accounting/model
      ↓
return result
```

## The three that matter most

With 30–45 minutes, these three reveal more than a list of features:

1. Why a wire-protocol proxy rather than a Postgres extension?
2. How does your scheduler guarantee fairness without destroying latency?
3. Tell me about the hardest correctness bug or race condition you hit.

## Be ready for

Not only what was built, but also what was deliberately left out, which tradeoffs were made, and where the architecture breaks down. That is what makes the project look impressive rather than over-engineered.
