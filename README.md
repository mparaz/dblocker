# dblocker

Database Blocker for AI Agents

`dblocker` is a SQL policy proxy. It listens on the Postgres wire protocol —
the de facto standard analytics tools use to talk to DuckDB — and sits in
front of a real Postgres-wire-compatible database. Every statement is
classified with [sqlglot](https://github.com/tobymao/sqlglot), checked against
a policy, and either forwarded under explicit limits or refused with a proper
Postgres error, before it reaches the database.

## What it does and does not establish

dblocker establishes **what was executed, under which policy, against which
pinned context, and how much came back**. It does not establish that an
agent's *interpretation* of the rows is correct — a query can be permitted,
bounded, recorded, and still be reasoned about wrongly. Consequential
conclusions still need human judgement.

It is also only a control if the agent cannot reach the database directly.
dblocker should hold the downstream credentials, and the downstream role
should be read-only regardless, so that the proxy is a narrowing of access
rather than the only thing standing in front of the data.

## Posture: deny by default

The policy is an allowlist over *statement classes*, not over table names.
That distinction is the whole design. An earlier version keyed policy off the
tables a statement referenced, which meant anything referencing no table —
`ATTACH`, `INSTALL`, `COPY ... TO`, `read_csv_auto('/etc/passwd')`,
`EXPORT DATABASE`, or SQL that simply failed to parse — matched no rule and
fell through to the default action.

So every statement is classified first:

| Class | Examples |
|---|---|
| `read` | `SELECT`, `WITH ... SELECT`, `SHOW`, `DESCRIBE`, `SUMMARIZE`, `EXPLAIN <read>` |
| `write` | `INSERT`, `UPDATE`, `DELETE`, `MERGE` |
| `ddl` | `CREATE`, `DROP`, `ALTER`, `TRUNCATE` |
| `admin` | `ATTACH`, `DETACH`, `INSTALL`, `COPY`, `PRAGMA` |
| `context` | `USE`, `SET` |
| `transaction` | `BEGIN`, `COMMIT`, `ROLLBACK` |
| `unknown` | unparseable SQL, and anything sqlglot cannot model |

`unknown` can never satisfy an allow rule. A statement whose effect dblocker
cannot establish is not forwarded on trust — which is why `EXPLAIN SELECT` is
a read while `EXPLAIN ANALYZE DELETE` (which really does run the delete) is
not.

## Controls

**Bounded execution.** One statement per request by default. Reads are capped
by rows and bytes: dblocker injects a `LIMIT` so the downstream stops early,
but the real guarantee is that results are *streamed* and cut off at the cap —
the earlier `fetchall()` pulled entire result sets into proxy memory before
anything looked at their size.

**Pinned context.** The effective catalog and schema are fixed by config and
re-applied on every pooled connection checkout. This matters because
`psycopg_pool` only rolls back transactions when a connection is returned — it
does not reset `search_path`, temp tables or loaded extensions, so without
this a session could inherit another session's schema while policy was still
evaluated against the pinned one. `USE` and `SET search_path` are refused by
default for the same reason; cosmetic client-handshake settings stay allowed
so ordinary drivers can still connect.

**Named capabilities.** Rather than composing SQL, an agent can ask for a
canonical query dblocker generates itself:

```sql
SELECT * FROM dblocker.capability('describe_table', 'analytics.events');
SELECT * FROM dblocker.capability('row_sample', 'analytics.events', '20');
```

Arguments are never handed to a SQL parser — identifiers are validated
character by character and rebuilt as AST nodes. Naming a capability grants no
extra reach: the rendered SQL goes back through the same policy, so
`row_sample` of an out-of-scope table is refused like any other read.

**Legible refusals.** Denials carry SQLSTATE `42501` (`insufficient_privilege`)
and a detail field naming the matched rule, so an agent can tell "policy
refused this" from "this SQL is invalid" without matching on message text.

**Bounded audit records.** Each decision is logged as JSON carrying a
`sql_sha256` rather than the statement text, plus the context hash, the policy
hash, the statement classes and the tables touched. Result rows are never
recorded.

## Rules

Rules are evaluated in order; the first whose predicates *all* hold decides the
query. Polarity lives only in `action`, so a rule's meaning never depends on
the name of its predicate.

```yaml
default_action: deny
rules:
  - name: allow-analytics-reads
    action: allow
    match:
      statement_class: [read]
      all_tables_in: { catalogs: [memory], schemas: [analytics] }
      reads_external_files: false
```

Predicates: `statement_class`, `all_tables_in` (**every** table must be in
scope), `tables_match` / `tables_not_match`, `reads_external_files`,
`writes_external_files`, `regex` / `not_regex`, `capability`.

Widening access means adding an allow rule, never removing a deny rule.
`default_action: allow` is refused at startup unless `allow_permissive_default:
true` confirms it is deliberate.

## Quickstart

```bash
uv sync

# A DuckDB downstream speaking the Postgres wire protocol.
uv run --group dev python -m buenavista.examples.duckdb_postgres

# dblocker in front of it, enforcing examples/dblocker.yaml.
uv run dblocker --config examples/dblocker.yaml

psql -h 127.0.0.1 -p 6432 -d memory
```

## Authentication

Set `auth.required` with users whose passwords come from the environment:

```yaml
auth:
  required: true
  users:
    - name: agent
      password_env: DBLOCKER_AGENT_PASSWORD
```

dblocker refuses at startup to bind a non-loopback address without
authentication. Note that the underlying wire implementation offers **md5**
authentication only, and dblocker does not terminate TLS — so for anything
beyond local use, run it on loopback behind an SSH tunnel or a TLS-terminating
proxy rather than exposing the port.

## Development

```bash
uv run ruff check . && uv run ruff format --check .
uv run ty check src
uv run pytest
```

`tests/test_bypass_corpus.py` holds every statement that defeated the earlier
table-based allowlist, each asserted denied. New evasion routes belong there
first.

## Not yet built

A durable evidence layer: an append-only JSONL ledger of provenance
(`query_id`, context hash, SQL hash, policy hash, timestamps, row/byte counts,
result digest, lifecycle status) with raw SQL kept in a separate
content-addressed owner-readable store, so records can be shared while the
statement text stays put. The decision records and canonical SQL that layer
needs are already produced; nothing persists them yet.
