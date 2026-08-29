# dblocker

Database Blocker for AI Agents

`dblocker` is a SQL policy proxy. It listens on the Postgres wire protocol —
the de facto standard analytics tools use to talk to DuckDB — and sits in
front of a real Postgres-wire-compatible database. Every statement is
classified with [sqlglot](https://github.com/tobymao/sqlglot), checked against
a policy, and either forwarded under explicit limits or refused with a proper
Postgres error, before it reaches the database.

There are two front-ends over one core: the **Postgres wire protocol**, so
psql, dbt and BI tools work unchanged, and an **MCP server**, so an agent gets
every result back with the provenance of the execution that produced it.

## What it does and does not establish

dblocker establishes **what was executed, under which policy, against which
pinned context, and what shape of result came back** — durably, in an
append-only ledger, with a digest that ties a reported figure to a recorded
execution.

It does not establish that an agent's *interpretation* of the rows is correct.
A query can be permitted, bounded, recorded, digested, and still be reasoned
about wrongly. Consequential conclusions still need human judgement.

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

## Evidence

Every query produces provenance in an append-only JSONL ledger: a `decision`
record written *before* execution, then an `outcome` record when the result
finishes streaming. Both share a `query_id`. A refusal writes one terminal
record and never touches the database.

The ledger carries hashes and counts. **The SQL text lives in a separate
content-addressed store**, owner-readable only, referenced by hash. That split
is the point: the ledger can be shipped to a reviewer or a pipeline while the
statement text stays with whoever ran it.

Never recorded: SQL text, result values, or downstream error *messages* — an
`error_class` is stored instead, because Postgres error text can quote row
values.

**Result digests.** Rows are hashed as they stream past, so a reviewer can
check that a figure an agent reported came from a recorded execution without
the figure ever being stored. Note precisely what this identifies: SQL without
`ORDER BY` has no guaranteed row order, so the digest identifies *what this
execution returned*, not a stable fingerprint of the query's answer.

**Truncation is reported honestly.** A result can be cut two ways — the stream
hits its cap, or dblocker's injected `LIMIT` stops the downstream first. The
second looks complete from the inside, so it is corrected explicitly:
`row_limit_applied` records that dblocker imposed a bound, and a result coming
back at exactly the cap is marked `truncated` rather than claimed whole.

**Fail closed, with one honest asymmetry.** If a decision cannot be written,
the query is refused (SQLSTATE `58030`) — an unrecorded query is worse than a
refused one. An *outcome* write failure cannot rescind a query whose rows are
already on the wire; it marks the ledger degraded, and queries are refused from
that point until it recovers. dblocker does not pretend the last one was atomic.

Read it back in-band: `SELECT * FROM dblocker.context()`,
`dblocker.queries('20')`, `dblocker.query('<id>')`, `dblocker.capabilities()`.
None of these reach the downstream.

## MCP

```bash
uv run dblocker mcp --config examples/dblocker.yaml   # stdio
```

Tools: `context_info`, `list_capabilities`, `capability`, `query`,
`recent_queries`, `query_record`.

A wire protocol has nowhere to put an evidence identifier — a result set is
just rows. An MCP tool returns a structured object, so every data result
arrives with its own envelope:

```json
{"columns": ["id","name"], "rows": [[1,"alpha"]],
 "evidence": {"query_id": "01a04d98...", "context_hash": "1941f776...",
              "policy_sha256": "2eb62e7b...", "sql_sha256": "3ec45f64...",
              "row_count": 1, "truncated": false, "result_sha256": "a8c4e24d..."}}
```

That is what lets an agent cite its evidence rather than merely have some.
Refusals come back as structured errors naming the rule, the reason and the
`query_id`.

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
uv run dblocker serve --config examples/dblocker.yaml

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

`tests/corpus.py` holds every statement that defeated the earlier table-based
allowlist. It is asserted denied three times over: against the policy engine,
through the whole engine path, and over MCP. New evasion routes belong there
first.

## Deliberately not built

**Result pagination and resume.** The tool this is modelled on can offer it
because the warehouse retains results server-side by query id. dblocker retains
no rows at all, so reproducing it would mean adding a result cache — which
would defeat the data minimisation that makes the ledger safe to share. The
result digest exists instead: it attests to what an execution returned without
keeping it.
