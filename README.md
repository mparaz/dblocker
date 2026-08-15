# dblocker

Database Blocker for AI Agents

`dblocker` is a SQL policy proxy. It listens on the Postgres wire protocol —
the de facto standard analytics tools use to talk to DuckDB — and sits in
front of a real Postgres-wire-compatible database server. Every query is
parsed with [sqlglot](https://github.com/tobymao/sqlglot), checked against a
list of configured rules, and either forwarded to the downstream database or
rejected with a normal Postgres error, before it ever reaches the database.

The first backend is [DuckDB](https://duckdb.org/), since DuckDB's dialect is
close to Postgres and it's what the author uses for analytics. Because
`dblocker` speaks the Postgres wire protocol on both sides, it should work
against any downstream that also speaks it.

## How it works

```
psql / BI tool ──(Postgres wire protocol)──> dblocker ──(Postgres wire protocol)──> downstream (DuckDB)
                                                 │
                                                 ├─ sqlglot: parse SQL, extract tables/schemas/statement type
                                                 └─ policy engine: evaluate rules -> allow / deny
```

`dblocker` does not run DuckDB itself — it proxies to an already-running
Postgres-wire-compatible endpoint in front of DuckDB, such as
[buenavista](https://github.com/jwills/buenavista)'s own DuckDB example
server, [duckdb-pgwire](https://github.com/euiko/duckdb-pgwire), or
[duckgres](https://github.com/PostHog/duckgres). `dblocker` is built on top
of buenavista's Postgres wire protocol implementation for the client-facing
side, and its Postgres backend (`psycopg`-based) for the downstream side.

## Rules

Rules live in a YAML config file (see `examples/dblocker.yaml`) and are
evaluated in order — the first matching rule decides the query's fate; if
none match, `default_action` applies. Four rule types are supported:

- `schema_allowlist` — deny any query that references a catalog/schema
  outside the given `schemas`/`catalogs` list. Unqualified table references
  are resolved against the session's current catalog/schema (tracked from
  `USE` statements).
- `table_denylist` — deny queries referencing tables matching a glob pattern
  over `catalog.schema.table`, e.g. `*.*.tmp_*`.
- `statement_type_block` — deny specific statement kinds, e.g.
  `["drop", "alter", "truncatetable"]`.
- `regex` — deny queries whose raw SQL text matches a pattern, for things
  the AST-based rules above don't model well.

Every statement in a multi-statement query batch is checked; the whole batch
is denied if any one statement violates a rule.

## Quickstart

```bash
uv sync

# In one terminal: a DuckDB downstream speaking the Postgres wire protocol.
uv run --group dev python -m buenavista.examples.duckdb_postgres

# In another: dblocker, listening in front of it with policy enforcement.
uv run dblocker --config examples/dblocker.yaml

# Then connect through dblocker instead of straight to the downstream:
psql -h localhost -p 6432
```

## Development

```bash
uv sync
uv run ruff check .
uv run ty check src
uv run pytest
```
