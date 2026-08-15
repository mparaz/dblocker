"""The policy-enforcing Postgres backend.

Subclasses buenavista's real Postgres backend (which already knows how to
speak to a downstream Postgres-wire server via psycopg) and inserts a policy
check in front of every `execute_sql` call.
"""

from __future__ import annotations

from typing import Any

from buenavista.backends.postgres import PGConnection, PGSession
from buenavista.core import QueryResult

from dblocker import policy
from dblocker.audit import record as record_audit
from dblocker.config import Rule
from dblocker.sql_analysis import ParsedQuery, analyze


class PolicyViolation(Exception):
    """Raised to deny a query. buenavista's wire protocol layer catches this
    and turns it into a normal Postgres ErrorResponse to the client."""


class PolicySession(PGSession):
    parent: PolicyConnection

    def __init__(self, parent: PolicyConnection, conn: Any) -> None:
        super().__init__(parent, conn)
        self.current_catalog = parent.default_catalog
        self.current_schema = parent.default_schema

    def execute_sql(self, sql: str, params=None) -> QueryResult:
        statements = analyze(
            sql,
            dialect=self.parent.dialect,
            default_catalog=self.current_catalog,
            default_schema=self.current_schema,
        )
        decision = policy.evaluate(statements, sql, self.parent.rules, self.parent.default_action)
        record_audit(session_id=str(self.id), sql=sql, decision=decision)
        if not decision.allowed:
            raise PolicyViolation(
                f"dblocker denied this query (rule={decision.rule_name or 'default'}): "
                f"{decision.reason}"
            )

        result = super().execute_sql(sql, params)
        self._apply_context_changes(statements)
        return result

    def _apply_context_changes(self, statements: list[ParsedQuery]) -> None:
        for statement in statements:
            if statement.sets_catalog:
                self.current_catalog = statement.sets_catalog
            if statement.sets_schema:
                self.current_schema = statement.sets_schema


class PolicyConnection(PGConnection):
    """A buenavista Postgres backend Connection that enforces policy before
    forwarding queries to the downstream Postgres-wire server."""

    def __init__(
        self,
        *,
        downstream_kwargs: dict[str, Any],
        rules: list[Rule],
        dialect: str,
        default_catalog: str,
        default_schema: str,
        default_action: str,
    ) -> None:
        super().__init__(conninfo="", **downstream_kwargs)
        self.rules = rules
        self.dialect = dialect
        self.default_catalog = default_catalog
        self.default_schema = default_schema
        self.default_action = default_action

    def new_session(self) -> PolicySession:
        conn = self.pool.getconn()
        conn.autocommit = True
        return PolicySession(self, conn)
