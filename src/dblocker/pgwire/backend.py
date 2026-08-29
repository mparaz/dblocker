"""The policy-enforcing Postgres backend.

Extends buenavista's Postgres backend -- which already speaks psycopg to a
downstream Postgres-wire server -- so that every statement passes through
classification, policy and bounds before it is forwarded.

The ordering inside `execute_sql` is the security-relevant part:

1. resolve a capability call to canonical SQL, if that is what this is;
2. classify and evaluate; refuse before touching the downstream;
3. bound the query, forward it, and stream the result under a cap;
4. only then update dblocker's view of the session context.
"""

from __future__ import annotations

from typing import Any, cast

from buenavista.backends.postgres import PGConnection, PGQueryResult, PGSession
from buenavista.core import QueryResult

from dblocker.audit import record_decision
from dblocker.core import policy
from dblocker.core.bounds import BoundedStream, apply_row_limit
from dblocker.core.capabilities import CapabilityError, parse_capability_call, render
from dblocker.core.classify import AnalyzedBatch, analyze
from dblocker.core.config import Config
from dblocker.core.context import SessionContext
from dblocker.core.decision import DecisionRecord, sql_digest
from dblocker.pgwire.errors import SQLSTATE_INTERNAL_ERROR, PolicyViolation


class PolicySession(PGSession):
    parent: PolicyConnection

    def __init__(self, parent: PolicyConnection, conn: Any) -> None:
        super().__init__(parent, conn)
        self.config = parent.config
        self.context = parent.context
        self.current_catalog = self.context.catalog
        self.current_schema = self.context.schema
        self.last_stream: BoundedStream | None = None
        self._apply_pinned_context()

    def _apply_pinned_context(self) -> None:
        """Force this pooled connection back to the pinned context.

        Connections are recycled, and psycopg_pool only rolls back
        transactions on return -- it does not reset search_path, temp tables or
        loaded extensions. Without this, a session could inherit another
        session's schema while dblocker still evaluated policy against the
        pinned one.

        These statements come from dblocker, not the caller, so they go
        straight to the superclass and are never policy-checked or audited as
        caller activity.
        """
        for statement in self.context.reset_statements():
            try:
                super().execute_sql(statement)
            except Exception:  # noqa: BLE001 - downstream may not support one
                # A downstream that rejects a reset statement (DuckDB has no
                # RESET ALL, Postgres has no USE) is not fatal; the remaining
                # statements still pin what they can.
                continue
        self._apply_statement_timeout()

    def _apply_statement_timeout(self) -> None:
        timeout = self.config.limits.statement_timeout_ms
        if timeout <= 0 or self.config.dialect == "duckdb":
            # DuckDB behind a Postgres-wire shim does not implement
            # statement_timeout; the row/byte caps remain the real bound there.
            return
        try:
            super().execute_sql(f"SET statement_timeout = {int(timeout)}")
        except Exception:  # noqa: BLE001
            pass

    def execute_sql(self, sql: str, params: Any = None) -> QueryResult:
        capability_name: str | None = None
        effective_sql = sql

        try:
            call = parse_capability_call(sql, dialect=self.config.dialect)
        except CapabilityError as exc:
            raise PolicyViolation(str(exc), sqlstate=SQLSTATE_INTERNAL_ERROR) from exc
        if call is not None:
            try:
                effective_sql = render(
                    call,
                    context=self.context,
                    enabled=self.config.capabilities_enabled,
                )
            except (CapabilityError, ValueError) as exc:
                raise PolicyViolation(str(exc), sqlstate=SQLSTATE_INTERNAL_ERROR) from exc
            capability_name = call.name

        batch = analyze(
            effective_sql,
            dialect=self.config.dialect,
            catalog=self.current_catalog,
            schema=self.current_schema,
        )
        decision = policy.evaluate(batch, effective_sql, self.config, capability=capability_name)
        record_decision(self._record(effective_sql, batch, decision, capability_name))

        if not decision.allowed:
            raise PolicyViolation(
                decision.message(),
                sqlstate=decision.sqlstate,
                detail=f"rule={decision.rule_name or 'default'}",
            )

        result = self._execute_bounded(effective_sql, params)
        self._apply_context_changes(batch)
        return result

    def _execute_bounded(self, sql: str, params: Any) -> QueryResult:
        limits = self.config.limits
        bounded_sql, _ = apply_row_limit(sql, dialect=self.config.dialect, max_rows=limits.max_rows)

        if params:
            self._cursor.execute(bounded_sql, params)
        else:
            self._cursor.execute(bounded_sql)

        status = self._cursor.statusmessage
        if self._cursor.description is None:
            self.last_stream = None
            return PGQueryResult([], [], status=status)

        stream = BoundedStream(
            max_rows=limits.max_rows,
            max_bytes=limits.max_bytes,
            batch_size=limits.fetch_batch_size,
        )
        self.last_stream = stream
        fields = [(d[0], self._bv_type(d[1])) for d in self._cursor.description]
        # PGQueryResult annotates `rows` as a list but only ever calls iter() on
        # it, so a generator satisfies the real contract and is what keeps the
        # result streaming rather than materialising it the way fetchall() did.
        rows = cast("list[list[Any | None]]", stream.rows(self._cursor))
        return PGQueryResult(fields, rows, status=status)

    @staticmethod
    def _bv_type(oid: int):
        from buenavista.backends.postgres import OID_TO_BVTYPE
        from buenavista.core import BVType

        return OID_TO_BVTYPE.get(oid, BVType.UNKNOWN)

    def _record(
        self,
        sql: str,
        batch: AnalyzedBatch,
        decision: Any,
        capability: str | None,
    ) -> DecisionRecord:
        tables = sorted(
            {table.qualified_name for statement in batch.statements for table in statement.tables}
        )
        return DecisionRecord(
            session_id=str(self.id),
            context_hash=self.context.context_hash(),
            policy_sha256=self.config.policy_sha256,
            sql_sha256=sql_digest(sql),
            decision="allow" if decision.allowed else "deny",
            rule_name=decision.rule_name,
            reason=decision.reason,
            statement_classes=[s.cls.value for s in batch.statements],
            tables=tables,
            capability=capability,
            reads_external_files=any(s.reads_external_files for s in batch.statements),
            writes_external_files=any(s.writes_external_files for s in batch.statements),
            statement_count=batch.statement_count,
            parse_error=batch.parse_error,
        )

    def _apply_context_changes(self, batch: AnalyzedBatch) -> None:
        if not self.config.context.allow_context_switch:
            return
        for statement in batch.statements:
            if statement.sets_catalog:
                self.current_catalog = statement.sets_catalog
            if statement.sets_schema:
                self.current_schema = statement.sets_schema


class PolicyConnection(PGConnection):
    """A buenavista backend Connection that enforces dblocker's policy."""

    def __init__(self, config: Config) -> None:
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

    def new_session(self) -> PolicySession:
        conn = self.pool.getconn()
        conn.autocommit = True
        return PolicySession(self, conn)
