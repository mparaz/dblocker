"""The MCP front-end.

Same core as the Postgres-wire proxy -- same classifier, policy, bounds and
ledger -- but a protocol that can carry provenance back with the answer. A wire
proxy has nowhere to put an evidence identifier: a result set is just rows. An
MCP tool returns a structured object, so every answer here arrives with the
`query_id`, hashes and result digest that identify the execution it came from.
That is what lets an agent cite its evidence rather than merely have some.

Refusals come back as structured errors naming the rule and reason, so an agent
can tell a policy decision from a malformed query without parsing prose.
"""

from __future__ import annotations

import logging
from typing import Any, LiteralString, cast

import psycopg
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from dblocker.core.capabilities import REGISTRY
from dblocker.core.config import Config
from dblocker.core.context import SessionContext
from dblocker.core.engine import DeniedError, Execution, QueryEngine
from dblocker.core.evidence import EvidenceLog

logger = logging.getLogger(__name__)

SESSION_ID = "mcp"


class PolicyDenied(ToolError):
    """A refusal, surfaced to the agent with its reason intact.

    Subclasses the SDK's `ToolError` rather than a bare Exception on purpose:
    the SDK treats anything else as a crash and withholds the message, whereas
    a policy decision is exactly what the agent needs to read -- which rule
    refused it, why, and the query_id to cite.
    """


class DownstreamSession:
    """One psycopg connection to the downstream, pinned to the context.

    The MCP server serves one agent over stdio and executes tool calls in
    sequence, so a single connection is enough; pooling would only reintroduce
    the cross-session state bleed the pgwire path has to defend against.
    """

    def __init__(self, config: Config, context: SessionContext, engine: QueryEngine) -> None:
        self.config = config
        self.context = context
        self.engine = engine
        self._connection: psycopg.Connection | None = None

    def cursor(self) -> Any:
        if self._connection is None or self._connection.closed:
            self._connection = self._connect()
        return self._connection.cursor()

    def _connect(self) -> psycopg.Connection:
        downstream = self.config.downstream
        connection = psycopg.connect(
            host=downstream.host,
            port=downstream.port,
            user=downstream.user,
            dbname=downstream.dbname,
            password=downstream.password(),
            autocommit=True,
        )
        cursor = connection.cursor()
        for statement in self.context.reset_statements():
            try:
                # psycopg wants a LiteralString to discourage dynamic SQL. These
                # statements are not caller input: they are built in
                # SessionContext.reset_statements() from a catalog and schema
                # that validate_identifier() has already checked and
                # quote_identifier() has quoted.
                cursor.execute(cast("LiteralString", statement))
            except Exception:  # noqa: BLE001 - downstream may not support one
                continue
        self.engine.apply_statement_timeout(cursor)
        return connection

    def close(self) -> None:
        if self._connection is not None and not self._connection.closed:
            self._connection.close()


def build_server(config: Config, evidence: EvidenceLog) -> MCPServer:
    context = SessionContext(
        downstream_host=config.downstream.host,
        downstream_port=config.downstream.port,
        downstream_user=config.downstream.user,
        downstream_dbname=config.downstream.dbname,
        catalog=config.context.catalog,
        schema=config.context.schema,
        dialect=config.dialect,
        policy_sha256=config.policy_sha256,
    )
    engine = QueryEngine(config=config, context=context, evidence=evidence)
    session = DownstreamSession(config, context, engine)
    mcp = MCPServer("dblocker")

    def shape(execution: Execution) -> dict[str, Any]:
        """Turn an Execution into a tool result carrying its own provenance."""
        if execution.is_static:
            columns = list(execution.static_fields or [])
            rows = [list(row) for row in execution.static_rows or []]
        else:
            columns = [d[0] for d in execution.description]
            # Materialised deliberately: the row cap already bounds this, and a
            # tool result has to be a value, not a stream.
            rows = [list(row) for row in (execution.rows or [])]
            if execution.stream is not None:
                execution.stream.finalize()

        return {
            "columns": columns,
            "rows": rows,
            "evidence": {
                "context_hash": context.context_hash(),
                "policy_sha256": config.policy_sha256,
                **execution.evidence(),
            },
        }

    def run_sql(sql: str) -> dict[str, Any]:
        try:
            return shape(engine.execute(sql, cursor=session.cursor(), session_id=SESSION_ID))
        except DeniedError as exc:
            raise PolicyDenied(
                f"{exc.decision.message()} [query_id={exc.query_id or '-'}]"
            ) from exc

    @mcp.tool()
    def context_info() -> dict[str, str]:
        """Show the pinned execution context and its hash.

        Every record this server writes carries the same context_hash, so this
        is how you confirm which endpoint, catalog, schema and policy your
        queries are running against.
        """
        return context.describe()

    @mcp.tool()
    def list_capabilities() -> list[dict[str, Any]]:
        """List the named canonical queries available, and whether each is enabled.

        Capabilities are rendered by dblocker from validated arguments, so they
        are the safest way to inspect structure. They grant no extra reach:
        their rendered SQL is subject to the same policy as anything else.
        """
        return [
            {
                "name": name,
                "description": description,
                "enabled": name in config.capabilities_enabled,
            }
            for name, (description, _) in sorted(REGISTRY.items())
        ]

    @mcp.tool()
    def capability(name: str, args: list[str] | None = None) -> dict[str, Any]:
        """Run a named capability, e.g. describe_table with 'analytics.events'.

        Returns rows plus an evidence envelope identifying the execution.
        """
        # Passed as values, never spliced into a SQL string for dblocker to
        # parse back: there is no text for an argument to break out of.
        try:
            return shape(
                engine.execute_capability(
                    name,
                    args or [],
                    cursor=session.cursor(),
                    session_id=SESSION_ID,
                )
            )
        except DeniedError as exc:
            raise PolicyDenied(
                f"{exc.decision.message()} [query_id={exc.query_id or '-'}]"
            ) from exc

    @mcp.tool()
    def query(sql: str) -> dict[str, Any]:
        """Run a read-only SQL statement under policy and row/byte caps.

        Returns rows plus an evidence envelope (query_id, SQL hashes, row
        count, truncation flag and a digest of the rows returned) so the result
        can be cited later. Refusals name the rule that refused them.
        """
        return run_sql(sql)

    @mcp.tool()
    def recent_queries(limit: int = 20) -> list[dict[str, Any]]:
        """List provenance records for recent queries in this session."""
        return evidence.recent(session_id=SESSION_ID, limit=limit)

    @mcp.tool()
    def query_record(query_id: str) -> list[dict[str, Any]]:
        """Fetch every provenance record for one query id.

        Metadata only -- no result rows are ever stored, which is why looking
        up any query id is safe.
        """
        return evidence.by_id(query_id)

    return mcp


def serve(config: Config, evidence: EvidenceLog) -> None:
    logger.info(
        "dblocker MCP server on stdio -> %s:%s | context=%s.%s | ledger=%s",
        config.downstream.host,
        config.downstream.port,
        config.context.catalog,
        config.context.schema,
        config.evidence.ledger_path if config.evidence.enabled else "disabled",
    )
    build_server(config, evidence).run()
