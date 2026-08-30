"""The single path every query takes, whichever front-end it arrived through.

Enforcement and recording live here rather than in a front-end so that the
Postgres-wire proxy and the MCP server cannot drift apart: one classifier, one
policy evaluation, one set of bounds, one ledger. A front-end's job is reduced
to speaking its protocol and shaping the result.

The order inside `execute` is security-relevant and must not be rearranged:

1. resolve an in-band `dblocker.*` call -- introspection answered here,
   capabilities rendered to canonical SQL;
2. classify and evaluate policy;
3. **write the decision record**, and refuse if it cannot be written;
4. refuse if policy said no -- before the downstream is touched at all;
5. bound the statement, execute it, and stream the result under a cap;
6. record the outcome when the stream finishes.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from dblocker.core import introspect, policy
from dblocker.core.bounds import BoundedStream, apply_row_limit
from dblocker.core.capabilities import (
    CapabilityCall,
    CapabilityError,
    DblockerCall,
    parse_dblocker_call,
)
from dblocker.core.capabilities import render as render_capability
from dblocker.core.classify import AnalyzedBatch, analyze
from dblocker.core.config import Config
from dblocker.core.context import SessionContext
from dblocker.core.decision import Decision, sql_digest
from dblocker.core.evidence import EvidenceLog, LedgerWriteError, new_query_id


class DeniedError(Exception):
    """Policy (or an unwritable ledger) refused the query."""

    def __init__(self, decision: Decision, *, query_id: str | None = None) -> None:
        super().__init__(decision.message())
        self.decision = decision
        self.query_id = query_id


@dataclass
class Execution:
    """What a front-end needs to serve one accepted query."""

    query_id: str
    decision: Decision
    canonical_sql: str
    sql_sha256: str
    canonical_sql_sha256: str
    # Raw DBAPI description; each front-end maps type codes for its protocol.
    description: Any = None
    rows: Iterator[list] | None = None
    stream: BoundedStream | None = None
    status: str | None = None
    capability: str | None = None
    row_limit_applied: bool = False
    # Set for in-band introspection, which is answered without a downstream.
    static_fields: list[str] | None = None
    static_rows: list[list[Any]] | None = None
    max_rows: int = 0

    @property
    def is_static(self) -> bool:
        return self.static_fields is not None

    def evidence(self) -> dict[str, Any]:
        """The envelope a caller can cite. Shape and hashes, never values."""
        summary = dict(self.stream.summary()) if self.stream else {}
        if self.stream is not None:
            # Same correction the ledger applies: an injected LIMIT can stop the
            # downstream before the stream reaches its cap, which would
            # otherwise look like a complete result.
            summary["truncated"] = bool(summary.get("truncated")) or (
                self.row_limit_applied and self.stream.row_count >= self.max_rows > 0
            )
            summary["row_limit_applied"] = self.row_limit_applied
        return {
            "query_id": self.query_id,
            "sql_sha256": self.sql_sha256,
            "canonical_sql_sha256": self.canonical_sql_sha256,
            "capability": self.capability,
            **summary,
        }


@dataclass
class QueryEngine:
    config: Config
    context: SessionContext
    evidence: EvidenceLog
    _statement_timeout_applied: bool = field(default=False, init=False)

    # -- public ------------------------------------------------------------

    def execute(
        self,
        sql: str,
        *,
        cursor: Any,
        session_id: str,
        params: Any = None,
    ) -> Execution:
        query_id = new_query_id()
        capability: str | None = None
        effective_sql = sql

        call = self._parse_call(sql)
        if call is not None and introspect.is_introspection(call):
            return self._introspect(call, query_id=query_id, session_id=session_id, sql=sql)
        if call is not None and call.func == "capability":
            effective_sql, capability = self._render_capability(call, sql)

        return self._enforce_and_run(
            effective_sql,
            submitted_sql=sql,
            capability=capability,
            query_id=query_id,
            cursor=cursor,
            session_id=session_id,
            params=params,
        )

    def execute_capability(
        self,
        name: str,
        args: list[str] | tuple[str, ...] = (),
        *,
        cursor: Any,
        session_id: str,
    ) -> Execution:
        """Invoke a capability from structured arguments.

        A front-end that already has the name and arguments as values (MCP)
        uses this rather than composing `dblocker.capability('...')` text for
        dblocker to parse straight back. Nothing the caller supplies is ever
        spliced into a SQL string.
        """
        query_id = new_query_id()
        capability_call = CapabilityCall(name=name.lower(), args=tuple(args))
        rendered = self._render_capability_call(capability_call)
        return self._enforce_and_run(
            rendered,
            # The caller wrote no SQL; what dblocker generated is the statement
            # of record, so it is both the submitted and the canonical form.
            submitted_sql=rendered,
            capability=capability_call.name,
            query_id=query_id,
            cursor=cursor,
            session_id=session_id,
            params=None,
        )

    def introspect(self, func: str, args: list[str] | tuple[str, ...], *, session_id: str):
        """Answer a `dblocker.*` introspection relation from structured args."""
        call = DblockerCall(func=func.lower(), args=tuple(args))
        if not introspect.is_introspection(call):
            raise DeniedError(
                Decision(allowed=False, rule_name=None, reason=f"unknown relation {func!r}")
            )
        return self._introspect(
            call, query_id=new_query_id(), session_id=session_id, sql=f"dblocker.{func}()"
        )

    def _enforce_and_run(
        self,
        effective_sql: str,
        *,
        submitted_sql: str,
        capability: str | None,
        query_id: str,
        cursor: Any,
        session_id: str,
        params: Any,
    ) -> Execution:
        batch = analyze(
            effective_sql,
            dialect=self.config.dialect,
            catalog=self.context.catalog,
            schema=self.context.schema,
        )
        decision = policy.evaluate(batch, effective_sql, self.config, capability=capability)

        if decision.allowed and self.evidence.degraded:
            # A previous outcome could not be recorded. Rather than keep serving
            # queries whose provenance would be missing, refuse until it clears.
            decision = Decision(
                allowed=False,
                rule_name=None,
                reason=(
                    "the evidence ledger is degraded after a failed write; "
                    "queries are refused until provenance can be recorded again"
                ),
            )

        canonical_sql = effective_sql
        row_limit_applied = False
        if decision.allowed:
            canonical_sql, row_limit_applied = apply_row_limit(
                effective_sql,
                dialect=self.config.dialect,
                max_rows=self.config.limits.max_rows,
            )

        record = self._decision_record(
            query_id=query_id,
            session_id=session_id,
            batch=batch,
            decision=decision,
            capability=capability,
            submitted_sql=submitted_sql,
            canonical_sql=canonical_sql,
        )
        self._write_decision(record, query_id)

        if not decision.allowed:
            raise DeniedError(decision, query_id=query_id)

        return self._run(
            canonical_sql,
            cursor=cursor,
            params=params,
            query_id=query_id,
            session_id=session_id,
            decision=decision,
            capability=capability,
            submitted_sql=submitted_sql,
            row_limit_applied=row_limit_applied,
        )

    def apply_statement_timeout(self, cursor: Any) -> None:
        """Best-effort per-session timeout, where the downstream supports it."""
        timeout = self.config.limits.statement_timeout_ms
        if timeout <= 0 or self.config.dialect == "duckdb":
            # DuckDB behind a Postgres-wire shim does not implement
            # statement_timeout; the row and byte caps remain the real bound.
            return
        try:
            cursor.execute(f"SET statement_timeout = {int(timeout)}")
        except Exception:  # noqa: BLE001 - downstream may not support it
            pass

    # -- internals ---------------------------------------------------------

    def _parse_call(self, sql: str):
        try:
            return parse_dblocker_call(sql, dialect=self.config.dialect)
        except CapabilityError as exc:
            raise DeniedError(Decision(allowed=False, rule_name=None, reason=str(exc))) from exc

    def _render_capability(self, call: Any, sql: str) -> tuple[str, str]:
        if not call.args:
            raise DeniedError(
                Decision(
                    allowed=False,
                    rule_name=None,
                    reason="dblocker.capability() needs a capability name",
                )
            )
        capability_call = CapabilityCall(name=call.args[0].lower(), args=call.args[1:])
        return self._render_capability_call(capability_call), capability_call.name

    def _render_capability_call(self, call: CapabilityCall) -> str:
        try:
            return render_capability(
                call,
                context=self.context,
                enabled=self.config.capabilities_enabled,
            )
        except (CapabilityError, ValueError) as exc:
            raise DeniedError(Decision(allowed=False, rule_name=None, reason=str(exc))) from exc

    def _introspect(self, call: Any, *, query_id: str, session_id: str, sql: str) -> Execution:
        try:
            fields, rows = introspect.dispatch(
                call,
                context=self.context,
                evidence=self.evidence,
                session_id=session_id,
                enabled_capabilities=self.config.capabilities_enabled,
            )
        except CapabilityError as exc:
            raise DeniedError(Decision(allowed=False, rule_name=None, reason=str(exc))) from exc

        digest = sql_digest(sql)
        # Recorded so the trail shows what an agent inspected, but marked as
        # introspection: it reads dblocker's own state, never user data.
        self.evidence.append(
            {
                "event": "introspection",
                "query_id": query_id,
                "session_id": session_id,
                "context_hash": self.context.context_hash(),
                "policy_sha256": self.config.policy_sha256,
                "relation": call.func,
                "sql_sha256": digest,
                "row_count": len(rows),
            },
            critical=False,
        )
        return Execution(
            query_id=query_id,
            decision=Decision(allowed=True, rule_name=None, reason="dblocker introspection"),
            canonical_sql=sql,
            sql_sha256=digest,
            canonical_sql_sha256=digest,
            static_fields=fields,
            static_rows=rows,
            status="SELECT",
        )

    def _write_decision(self, record: dict[str, Any], query_id: str) -> None:
        try:
            self.evidence.append(record, critical=True)
        except LedgerWriteError as exc:
            # Fail closed: a query nobody can later account for does not run.
            raise DeniedError(
                Decision(
                    allowed=False,
                    rule_name=None,
                    reason=f"provenance could not be recorded, so the query was refused: {exc}",
                ),
                query_id=query_id,
            ) from exc

    def _decision_record(
        self,
        *,
        query_id: str,
        session_id: str,
        batch: AnalyzedBatch,
        decision: Decision,
        capability: str | None,
        submitted_sql: str,
        canonical_sql: str,
    ) -> dict[str, Any]:
        submitted_hash, submitted_ref = self.evidence.store_sql(submitted_sql)
        if canonical_sql == submitted_sql:
            canonical_hash, canonical_ref = submitted_hash, submitted_ref
        else:
            canonical_hash, canonical_ref = self.evidence.store_sql(canonical_sql)

        tables = sorted(
            {table.qualified_name for statement in batch.statements for table in statement.tables}
        )
        return {
            "event": "decision",
            "query_id": query_id,
            "session_id": session_id,
            "context_hash": self.context.context_hash(),
            "policy_sha256": self.config.policy_sha256,
            "decision": "allow" if decision.allowed else "deny",
            "status": None if decision.allowed else "denied",
            "rule_name": decision.rule_name,
            "reason": decision.reason,
            "capability": capability,
            "statement_classes": [s.cls.value for s in batch.statements],
            "tables": tables,
            "reads_external_files": any(s.reads_external_files for s in batch.statements),
            "writes_external_files": any(s.writes_external_files for s in batch.statements),
            "statement_count": batch.statement_count,
            "parse_error": batch.parse_error,
            "sql_sha256": submitted_hash,
            "canonical_sql_sha256": canonical_hash,
            "sql_ref": submitted_ref,
            "canonical_sql_ref": canonical_ref,
        }

    def _run(
        self,
        canonical_sql: str,
        *,
        cursor: Any,
        params: Any,
        query_id: str,
        session_id: str,
        decision: Decision,
        capability: str | None,
        submitted_sql: str,
        row_limit_applied: bool = False,
    ) -> Execution:
        started = time.monotonic()
        try:
            if params:
                cursor.execute(canonical_sql, params)
            else:
                cursor.execute(canonical_sql)
        except Exception as exc:
            # The error *class* is recorded, never its message: downstream error
            # text can quote row values, which have no business in the ledger.
            self._record_outcome(
                query_id=query_id,
                session_id=session_id,
                status="failed",
                started=started,
                error=exc,
            )
            raise

        status = getattr(cursor, "statusmessage", None)
        execution = Execution(
            query_id=query_id,
            decision=decision,
            canonical_sql=canonical_sql,
            sql_sha256=sql_digest(submitted_sql),
            canonical_sql_sha256=sql_digest(canonical_sql),
            description=cursor.description,
            status=status,
            capability=capability,
            row_limit_applied=row_limit_applied,
            max_rows=self.config.limits.max_rows,
        )

        if cursor.description is None:
            self._record_outcome(
                query_id=query_id, session_id=session_id, status="succeeded", started=started
            )
            return execution

        limits = self.config.limits

        def complete(stream: BoundedStream) -> None:
            # A result can be cut short two ways, and both must be reported.
            # The stream may hit its cap, or -- easy to miss -- the injected
            # LIMIT may have stopped the downstream first, in which case the
            # stream ends naturally and looks complete. Coming back with
            # exactly the cap after dblocker imposed one means there may well
            # be more rows, so the record must not claim a whole result.
            cut_by_limit = row_limit_applied and stream.row_count >= limits.max_rows > 0
            truncated = stream.truncated or cut_by_limit
            self._record_outcome(
                query_id=query_id,
                session_id=session_id,
                status="truncated" if truncated else "succeeded",
                started=started,
                stream=stream,
                truncated=truncated,
                row_limit_applied=row_limit_applied,
            )

        stream = BoundedStream(
            max_rows=limits.max_rows,
            max_bytes=limits.max_bytes,
            batch_size=limits.fetch_batch_size,
            digest_rows=self.config.evidence.result_digest,
            on_complete=complete,
        )
        execution.stream = stream
        execution.rows = stream.rows(cursor)
        return execution

    def _record_outcome(
        self,
        *,
        query_id: str,
        session_id: str,
        status: str,
        started: float,
        stream: BoundedStream | None = None,
        error: BaseException | None = None,
        truncated: bool | None = None,
        row_limit_applied: bool = False,
    ) -> None:
        record: dict[str, Any] = {
            "event": "outcome",
            "query_id": query_id,
            "session_id": session_id,
            "context_hash": self.context.context_hash(),
            "status": status,
            "duration_ms": round((time.monotonic() - started) * 1000, 3),
        }
        if stream is not None:
            record.update(stream.summary())
            record["row_limit_applied"] = row_limit_applied
            if truncated is not None:
                # Overrides the stream's own view, which cannot see a LIMIT
                # that stopped the downstream before the stream reached its cap.
                record["truncated"] = truncated
        if error is not None:
            sqlstate = getattr(error, "sqlstate", None)
            record["error_class"] = (
                f"{type(error).__name__}/{sqlstate}" if sqlstate else type(error).__name__
            )
        self.evidence.append(record, critical=False)
