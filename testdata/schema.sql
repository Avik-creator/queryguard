-- QueryGuard test schema: a multi-tenant shop whose data is skewed on
-- purpose, so the same query costs very different amounts per tenant.
--
-- Run by testdata/initdb/load.sh with psql variables:
--   :customers  number of customers  (default 1,000,000)
--   :orders     number of orders     (default 10,000,000)

CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Same seed on every load, so the data is reproducible.
SELECT setseed(0.42);

-- Tables are created without indexes or foreign keys. Building them once
-- after the load is much faster than updating them row by row.

CREATE TABLE tenants (
    id   int  NOT NULL,
    name text NOT NULL,
    plan text NOT NULL CHECK (plan IN ('free', 'pro', 'enterprise'))
);

CREATE TABLE customers (
    id         bigint      GENERATED ALWAYS AS IDENTITY,
    tenant_id  int         NOT NULL,
    email      text        NOT NULL,
    country    text        NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE orders (
    id          bigint      GENERATED ALWAYS AS IDENTITY,
    tenant_id   int         NOT NULL,
    customer_id bigint      NOT NULL,
    status      text        NOT NULL
        CHECK (status IN ('pending', 'paid', 'shipped', 'delivered', 'cancelled')),
    total_cents bigint      NOT NULL,
    note        text,
    created_at  timestamptz NOT NULL
);

-- 100 tenants. Tenant 1 is the largest; sizes fall off steeply after it.
INSERT INTO tenants (id, name, plan)
SELECT i,
       'tenant_' || i,
       CASE WHEN i <= 5 THEN 'enterprise' WHEN i <= 30 THEN 'pro' ELSE 'free' END
FROM generate_series(1, 100) AS i;

-- ceil(100 * r^3) for uniform r puts about 21.5% of rows in tenant 1 and
-- about 0.3% in tenant 100.
INSERT INTO customers (tenant_id, email, country, created_at)
SELECT greatest(1, ceil(100 * power(r1, 3)))::int,
       'user' || i || '@example.com',
       CASE WHEN r2 < 0.40 THEN 'US' WHEN r2 < 0.55 THEN 'IN' WHEN r2 < 0.65 THEN 'DE'
            WHEN r2 < 0.75 THEN 'GB' WHEN r2 < 0.85 THEN 'BR' ELSE 'FR' END,
       timestamptz '2024-10-01' + (i::float8 / :customers) * interval '730 days'
FROM (SELECT i, random() AS r1, random() AS r2
      FROM generate_series(1, :customers) AS i) AS g;

-- Each order belongs to a random customer and takes that customer's tenant.
-- Most orders are delivered and few are pending, as in a real shop, so the
-- planner sees very different row counts depending on the status filter.
INSERT INTO orders (tenant_id, customer_id, status, total_cents, note, created_at)
SELECT c.tenant_id,
       c.id,
       CASE WHEN g.r1 < 0.80 THEN 'delivered' WHEN g.r1 < 0.92 THEN 'shipped'
            WHEN g.r1 < 0.97 THEN 'paid' WHEN g.r1 < 0.99 THEN 'pending'
            ELSE 'cancelled' END,
       (500 + g.r2 * g.r2 * 99500)::bigint,
       CASE WHEN g.r3 < 0.30 THEN md5(g.i::text) END,
       timestamptz '2024-10-01' + (g.i::float8 / :orders) * interval '730 days'
FROM (SELECT i,
             1 + floor(random() * :customers)::bigint AS customer_id,
             random() AS r1, random() AS r2, random() AS r3
      FROM generate_series(1, :orders) AS i) AS g
JOIN customers AS c ON c.id = g.customer_id;

-- Keys, indexes and foreign keys, built once now that the data is in.
SET maintenance_work_mem = '512MB';

ALTER TABLE tenants   ADD PRIMARY KEY (id);
ALTER TABLE customers ADD PRIMARY KEY (id);
ALTER TABLE orders    ADD PRIMARY KEY (id);

CREATE UNIQUE INDEX customers_tenant_email_idx ON customers (tenant_id, email);
CREATE INDEX orders_tenant_created_idx ON orders (tenant_id, created_at);
CREATE INDEX orders_customer_idx ON orders (customer_id);
-- Small partial index: only the ~2% of orders still pending.
CREATE INDEX orders_pending_idx ON orders (created_at) WHERE status = 'pending';
-- No index on total_cents or note, on purpose: filtering on them forces a
-- full scan, which is how the load generator makes expensive queries.

ALTER TABLE customers ADD FOREIGN KEY (tenant_id)   REFERENCES tenants;
ALTER TABLE orders    ADD FOREIGN KEY (tenant_id)   REFERENCES tenants;
ALTER TABLE orders    ADD FOREIGN KEY (customer_id) REFERENCES customers;

-- Fresh statistics for the planner, and a visibility map so index-only
-- scans behave as they would on a settled production table.
VACUUM (ANALYZE) tenants, customers, orders;
