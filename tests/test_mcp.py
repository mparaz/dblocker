"""The MCP front-end must enforce identically to pgwire, and say more.

The point of this front-end is that a tool result is a structured object, so
every answer can carry the provenance of the execution that produced it --
something a row set on a wire protocol cannot express. These tests check both
halves: the same verdicts, plus an evidence envelope on every data result.
"""

from __future__ import annotations

import asyncio

import pytest
from corpus import MUST_DENY
from mcp.server.mcpserver.exceptions import ToolError

from dblocker.core.config import load_config
from dblocker.core.evidence import EvidenceConfig, EvidenceLog
from dblocker.mcp.server import PolicyDenied, build_server


class FakeCursor:
    def __init__(self, rows, description):
        self._rows = list(rows)
        self.description = description
        self.statusmessage = "SELECT"
        self.executed: list[str] = []
        self.position = 0

    def execute(self, sql, params=None):
        self.executed.append(sql)

    def fetchmany(self, size):
        batch = self._rows[self.position : self.position + size]
        self.position += len(batch)
        return batch


@pytest.fixture
def server(tmp_path, monkeypatch):
    config = load_config("examples/dblocker.yaml")
    config.evidence = EvidenceConfig(
        ledger_path=tmp_path / "ledger.jsonl", sql_store_path=tmp_path / "sql"
    )
    evidence = EvidenceLog(config.evidence)
    evidence.prepare()

    cursor = FakeCursor([(1, "alpha"), (2, "beta")], [("id", 23), ("name", 25)])
    # No downstream in unit tests: hand the session a cursor directly.
    monkeypatch.setattr(
        "dblocker.mcp.server.DownstreamSession.cursor", lambda self: cursor, raising=True
    )
    mcp = build_server(config, evidence)
    mcp._test_cursor = cursor
    mcp._test_evidence = evidence
    return mcp


def tools(server) -> dict:
    return {tool.name: tool for tool in asyncio.run(server.list_tools())}


def call(server, tool, /, **arguments):
    """Invoke a tool and return its structured payload.

    Positional-only so a tool's own argument names (`name`, `sql`, ...) cannot
    collide with this helper's parameters.

    A tool that returns a non-dict (a list, say) is wrapped by the SDK under a
    "result" key, so unwrap that to give tests the value the tool returned.
    """
    outcome = asyncio.run(server.call_tool(tool, arguments))
    assert not outcome.is_error, f"{tool} failed: {outcome.content}"
    data = outcome.structured_content
    if isinstance(data, dict) and set(data) == {"result"}:
        return data["result"]
    return data


def denial(server, tool, /, **arguments) -> str:
    """Call a tool expecting a refusal, and return the message the agent sees."""
    with pytest.raises(ToolError) as caught:
        asyncio.run(server.call_tool(tool, arguments))
    return str(caught.value)


# -- surface -----------------------------------------------------------------


def test_the_expected_tools_are_exposed(server):
    assert set(tools(server)) == {
        "context_info",
        "list_capabilities",
        "capability",
        "query",
        "recent_queries",
        "query_record",
    }


def test_every_tool_is_documented(server):
    for tool in tools(server).values():
        assert tool.description and len(tool.description.strip()) > 20


# -- evidence envelope -------------------------------------------------------


def test_a_query_returns_rows_with_their_provenance(server):
    data = call(server, "query", sql="SELECT * FROM analytics.events")
    assert data["columns"] == ["id", "name"]
    assert data["rows"] == [[1, "alpha"], [2, "beta"]]

    evidence = data["evidence"]
    # This envelope is the whole reason for the MCP front-end: the answer
    # arrives already carrying the identity of the execution behind it.
    for key in (
        "query_id",
        "context_hash",
        "policy_sha256",
        "sql_sha256",
        "canonical_sql_sha256",
        "row_count",
        "truncated",
        "result_sha256",
    ):
        assert evidence.get(key) is not None, key
    assert evidence["row_count"] == 2
    assert evidence["truncated"] is False


def test_the_evidence_id_resolves_to_ledger_records(server):
    data = call(server, "query", sql="SELECT * FROM analytics.events")
    query_id = data["evidence"]["query_id"]

    records = call(server, "query_record", query_id=query_id)
    assert [r["event"] for r in records] == ["decision", "outcome"]
    assert records[1]["result_sha256"] == data["evidence"]["result_sha256"]


def test_the_result_digest_ties_a_figure_to_an_execution(server):
    """Same rows, same digest -- so a reported number can be checked later."""
    first = call(server, "query", sql="SELECT * FROM analytics.events")
    server._test_cursor.position = 0
    second = call(server, "query", sql="SELECT * FROM analytics.events")
    assert first["evidence"]["result_sha256"] == second["evidence"]["result_sha256"]
    assert first["evidence"]["query_id"] != second["evidence"]["query_id"]


# -- enforcement parity ------------------------------------------------------


@pytest.mark.parametrize("sql,why", MUST_DENY, ids=[s for s, _ in MUST_DENY])
def test_bypasses_are_denied_over_mcp_too(server, sql, why):
    assert "dblocker denied" in denial(server, "query", sql=sql), why


def test_a_refusal_names_the_rule_and_the_query_id(server):
    """A refusal must be readable by the agent, not swallowed as a crash.

    PolicyDenied subclasses the SDK's ToolError precisely so the reason
    survives; a plain exception would reach the agent as "Error executing
    tool" with the explanation stripped.
    """
    message = denial(server, "query", sql="SELECT * FROM secure.secrets")
    assert issubclass(PolicyDenied, ToolError)
    assert "dblocker denied" in message
    assert "query_id=" in message
    assert "rule=" in message


def test_a_denied_query_never_reaches_the_downstream(server):
    denial(server, "query", sql="DROP TABLE analytics.events")
    assert server._test_cursor.executed == []


# -- capabilities ------------------------------------------------------------


def test_capabilities_are_listed_with_their_enabled_state(server):
    listed = call(server, "list_capabilities")
    names = {entry["name"] for entry in listed}
    assert {"describe_table", "row_sample", "list_tables"} <= names
    assert all("description" in entry for entry in listed)


def test_a_capability_runs_and_carries_its_name_in_the_evidence(server):
    data = call(server, "capability", name="row_sample", args=["analytics.events"])
    assert data["evidence"]["capability"] == "row_sample"
    assert data["rows"]


def test_a_capability_cannot_reach_outside_the_allowed_scope(server):
    message = denial(server, "capability", name="row_sample", args=["secure.secrets"])
    assert "dblocker denied" in message


def test_capability_arguments_cannot_break_out_of_the_generated_sql(server):
    """Arguments are passed as values, so there is no SQL text to escape."""
    denial(server, "capability", name="row_sample", args=["analytics.events'); DROP TABLE x--"])
    assert all("DROP" not in sql for sql in server._test_cursor.executed)


# -- context and history -----------------------------------------------------


def test_context_info_reports_the_pinned_context(server):
    described = call(server, "context_info")
    assert described["catalog"] == "memory"
    assert described["schema"] == "analytics"
    assert described["context_hash"]


def test_recent_queries_lists_this_session_s_work(server):
    call(server, "query", sql="SELECT * FROM analytics.events")
    records = call(server, "recent_queries", limit=10)
    assert records and all(r["session_id"] == "mcp" for r in records)
