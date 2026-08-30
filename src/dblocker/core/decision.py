"""Policy decisions and the record shape that outlives them.

`DecisionRecord` is deliberately shaped as the provenance row the (not yet
built) evidence ledger will append: it carries a SHA-256 of the SQL rather than
the SQL text itself, so that a record can be written somewhere shared while the
statement text stays with its owner.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

# Postgres SQLSTATE for insufficient_privilege. Sending a real SQLSTATE lets an
# agent tell "policy refused me" apart from "I wrote invalid SQL", which a bare
# error message cannot express.
SQLSTATE_INSUFFICIENT_PRIVILEGE = "42501"


def sql_digest(sql: str) -> str:
    return hashlib.sha256(sql.encode("utf-8")).hexdigest()


@dataclass
class Decision:
    allowed: bool
    rule_name: str | None
    reason: str

    @property
    def sqlstate(self) -> str:
        return SQLSTATE_INSUFFICIENT_PRIVILEGE

    def message(self) -> str:
        return f"dblocker denied this query (rule={self.rule_name or 'default'}): {self.reason}"


@dataclass
class DecisionRecord:
    """Bounded, durable-shaped facts about one policy decision.

    Deliberately excludes the SQL text and any result data.
    """

    session_id: str
    context_hash: str
    policy_sha256: str
    sql_sha256: str
    decision: str
    rule_name: str | None
    reason: str
    statement_classes: list[str] = field(default_factory=list)
    tables: list[str] = field(default_factory=list)
    capability: str | None = None
    reads_external_files: bool = False
    writes_external_files: bool = False
    statement_count: int = 0
    parse_error: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
