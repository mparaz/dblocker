"""Relations that let a caller read dblocker's own state and record.

    SELECT * FROM dblocker.context();
    SELECT * FROM dblocker.queries('20');
    SELECT * FROM dblocker.query('0193f...');

None of these reach the downstream. They return `(fields, rows)` so each
front-end can wrap them in whatever result type it speaks.

`context()` is the advisory half of context confirmation: it lets an agent (or
a reviewer) see exactly which endpoint, catalog, schema and policy a session is
pinned to, and the hash that identifies that combination. Nothing forces a
caller to look -- forcing it would break every ordinary client -- but the same
hash is recorded on every ledger entry, so what a query ran against is
established whether or not anyone asked.

`query()` is not scoped to the calling session. That is safe by construction:
the ledger holds no row data, so another session's provenance discloses nothing
about its results.
"""

from __future__ import annotations

import json
from typing import Any

from dblocker.core.capabilities import REGISTRY, CapabilityError, DblockerCall
from dblocker.core.context import SessionContext
from dblocker.core.evidence import EvidenceLog

Fields = list[str]
Rows = list[list[Any]]
Relation = tuple[Fields, Rows]

INTROSPECTION_FUNCS = frozenset({"context", "queries", "query", "capabilities"})

DEFAULT_QUERY_LIMIT = 20
MAX_QUERY_LIMIT = 1000


def is_introspection(call: DblockerCall) -> bool:
    return call.func in INTROSPECTION_FUNCS


def dispatch(
    call: DblockerCall,
    *,
    context: SessionContext,
    evidence: EvidenceLog,
    session_id: str,
    enabled_capabilities: list[str],
) -> Relation:
    if call.func == "context":
        return _context(call, context)
    if call.func == "capabilities":
        return _capabilities(call, enabled_capabilities)
    if call.func == "queries":
        return _queries(call, evidence, session_id)
    if call.func == "query":
        return _query(call, evidence)
    raise CapabilityError(f"unknown dblocker relation {call.func!r}")


def _require_args(call: DblockerCall, minimum: int, maximum: int) -> None:
    if not minimum <= len(call.args) <= maximum:
        raise CapabilityError(
            f"dblocker.{call.func}() takes between {minimum} and {maximum} "
            f"argument(s), got {len(call.args)}"
        )


def _context(call: DblockerCall, context: SessionContext) -> Relation:
    _require_args(call, 0, 0)
    described = context.describe()
    return ["key", "value"], [[key, value] for key, value in sorted(described.items())]


def _capabilities(call: DblockerCall, enabled: list[str]) -> Relation:
    _require_args(call, 0, 0)
    rows = [
        [name, description, name in enabled] for name, (description, _) in sorted(REGISTRY.items())
    ]
    return ["capability", "description", "enabled"], rows


def _parse_limit(call: DblockerCall) -> int:
    if not call.args:
        return DEFAULT_QUERY_LIMIT
    try:
        limit = int(call.args[0])
    except (TypeError, ValueError) as exc:
        raise CapabilityError(f"dblocker.{call.func}() takes an integer limit") from exc
    if not 1 <= limit <= MAX_QUERY_LIMIT:
        raise CapabilityError(f"limit must be between 1 and {MAX_QUERY_LIMIT}")
    return limit


_RECORD_FIELDS = [
    "query_id",
    "ts",
    "event",
    "decision",
    "status",
    "rule_name",
    "reason",
    "capability",
    "tables",
    "row_count",
    "truncated",
    "result_sha256",
    "sql_sha256",
    "context_hash",
]


def _as_row(record: dict[str, Any]) -> list[Any]:
    row: list[Any] = []
    for name in _RECORD_FIELDS:
        value = record.get(name)
        row.append(json.dumps(value) if isinstance(value, list | dict) else value)
    return row


def _queries(call: DblockerCall, evidence: EvidenceLog, session_id: str) -> Relation:
    _require_args(call, 0, 1)
    limit = _parse_limit(call)
    records = evidence.recent(session_id=session_id, limit=limit)
    return _RECORD_FIELDS, [_as_row(record) for record in records]


def _query(call: DblockerCall, evidence: EvidenceLog) -> Relation:
    _require_args(call, 1, 1)
    records = evidence.by_id(call.args[0])
    return _RECORD_FIELDS, [_as_row(record) for record in records]
