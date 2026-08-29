"""The Postgres-wire front-end.

Extends buenavista's Postgres backend -- which already speaks psycopg to a
downstream Postgres-wire server -- and delegates every statement to
`QueryEngine`. All enforcement and recording lives in the engine, shared with
the MCP front-end; what remains here is protocol work: mapping type OIDs,
turning a refusal into an ErrorResponse, and handing buenavista a row iterator.
"""

from __future__ import annotations

from typing import Any, cast

from buenavista.backends.postgres import OID_TO_BVTYPE, PGConnection, PGQueryResult, PGSession
from buenavista.core import BVType, QueryResult

from dblocker.core.bounds import BoundedStream
from dblocker.core.config import Config
from dblocker.core.context import SessionContext
from dblocker.core.engine import DeniedError, Execution, QueryEngine
from dblocker.core.evidence import EvidenceLog
from dblocker.pgwire.errors import SQLSTATE_LEDGER_UNAVAILABLE, PolicyViolation


class PolicySession(PGSession):
    parent: PolicyConnection

    def __init__(self, parent: PolicyConnection, conn: Any) -> None:
        super().__init__(parent, conn)
        self.config = parent.config
        self.context = parent.context
        self.engine = parent.engine
        self.last_stream: BoundedStream | None = None
        self._apply_pinned_context()

    def _apply_pinned_context(self) -> None:
        """Force this pooled connection back to the pinned context.

        Connections are recycled, and psycopg_pool only rolls back
        transactions on return -- it does not reset search_path, temp tables or
        loaded extensions. Without this, a session could inherit another
        session's schema while policy was still evaluated against the pinned
        one.

        These statements come from dblocker, not the caller, so they bypass the
        engine entirely and are never recorded as caller activity.
        """
        for statement in self.context.reset_statements():
            try:
                super().execute_sql(statement)
            except Exception:  # noqa: BLE001 - downstream may not support one
                # A downstream that rejects a reset statement (DuckDB has no
                # RESET ALL, Postgres has no USE) is not fatal; the remaining
                # statements still pin what they can.
                continue
        self.engine.apply_statement_timeout(self._cursor)

    def execute_sql(self, sql: str, params: Any = None) -> QueryResult:
        # A previous result the client abandoned mid-stream still owes an
        # outcome record; settle it before starting another query.
        self._finalize_previous()
        try:
            execution = self.engine.execute(
                sql, cursor=self._cursor, session_id=str(self.id), params=params
            )
        except DeniedError as exc:
            raise self._as_violation(exc) from exc

        if execution.is_static:
            return self._static_result(execution)

        self.last_stream = execution.stream
        fields = [(d[0], OID_TO_BVTYPE.get(d[1], BVType.UNKNOWN)) for d in execution.description]
        # PGQueryResult annotates `rows` as a list but only ever calls iter() on
        # it, so a generator satisfies the real contract and is what keeps the
        # result streaming rather than materialising it the way fetchall() did.
        rows = cast("list[list[Any | None]]", execution.rows)
        return PGQueryResult(fields, rows, status=execution.status)

    def close(self) -> None:
        self._finalize_previous()
        super().close()

    def _finalize_previous(self) -> None:
        if self.last_stream is not None:
            self.last_stream.finalize()
            self.last_stream = None

    @staticmethod
    def _as_violation(exc: DeniedError) -> PolicyViolation:
        decision = exc.decision
        # A refusal caused by an unwritable ledger is not a permissions problem,
        # so it gets io_error rather than insufficient_privilege -- an agent
        # should retry that one, not rewrite its query.
        ledger_problem = "provenance could not be recorded" in decision.reason
        return PolicyViolation(
            decision.message(),
            sqlstate=SQLSTATE_LEDGER_UNAVAILABLE if ledger_problem else decision.sqlstate,
            detail=f"rule={decision.rule_name or 'default'} query_id={exc.query_id or '-'}",
        )

    @staticmethod
    def _static_result(execution: Execution) -> QueryResult:
        fields = [(name, BVType.TEXT) for name in execution.static_fields or []]
        rows = [[None if v is None else str(v) for v in row] for row in execution.static_rows or []]
        return PGQueryResult(fields, rows, status=execution.status)


class PolicyConnection(PGConnection):
    """A buenavista backend Connection that enforces dblocker's policy."""

    def __init__(self, config: Config, evidence: EvidenceLog) -> None:
        downstream = config.downstream
        kwargs: dict[str, Any] = {
            "host": downstream.host,
            "port": downstream.port,
            "user": downstream.user,
            "dbname": downstream.dbname,
        }
        password = downstream.password()
        if password:
            kwargs["password"] = password
        super().__init__(conninfo="", **kwargs)

        self.config = config
        self.evidence = evidence
        self.context = SessionContext(
            downstream_host=downstream.host,
            downstream_port=downstream.port,
            downstream_user=downstream.user,
            downstream_dbname=downstream.dbname,
            catalog=config.context.catalog,
            schema=config.context.schema,
            dialect=config.dialect,
            policy_sha256=config.policy_sha256,
        )
        self.engine = QueryEngine(config=config, context=self.context, evidence=evidence)

    def new_session(self) -> PolicySession:
        conn = self.pool.getconn()
        conn.autocommit = True
        return PolicySession(self, conn)
