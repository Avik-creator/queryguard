#!/usr/bin/env bash
# Loads the test schema. The Postgres image runs every script in
# /docker-entrypoint-initdb.d once, the first time it starts with an empty
# data directory. Set QG_CUSTOMERS and QG_ORDERS for a smaller data set.
set -euo pipefail

psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -v ON_ERROR_STOP=1 \
    -v customers="${QG_CUSTOMERS:-1000000}" \
    -v orders="${QG_ORDERS:-10000000}" \
    -f /queryguard/schema.sql
