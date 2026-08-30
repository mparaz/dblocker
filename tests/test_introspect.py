from __future__ import annotations

import json

import pytest

from dblocker.core.capabilities import CapabilityError, parse_dblocker_call
from dblocker.core.config import load_config
from dblocker.core.context import SessionContext
from dblocker.core.engine import DeniedError, QueryEngine
from dblocker.core.evidence import EvidenceConfig, EvidenceLog

SESSION = "test-session"


class FakeCursor:
    description = None
    statusmessage = "SELECT"

    def __init__(self):
        self.executed: list[str] = []

    def execute(self, sql, params=None):
        self.executed.append(sql)

    def fetchmany(self, size):
        return []


@pytest.fixture
def engine(tmp_path):
    config = load_config("examples/dblocker.yaml")
    config.evidence = EvidenceConfig(
        ledger_path=tmp_path / "ledger.jsonl", sql_store_path=tmp_path / "sql"
    )
    evidence = EvidenceLog(config.evidence)
    evidence.prepare()
    context = SessionContext(
        downstream_host="localhost",
        downstream_port=5433,
        downstream_user="u",
        downstream_dbname="memory",
        catalog=config.context.catalog,
        schema=config.context.schema,
        dialect=config.dialect,
        policy_sha256=config.policy_sha256,
    )
    return QueryEngine(config=config, context=context, evidence=evidence)


def call(engine, sql: str, cursor=None):
    return engine.execute(sql, cursor=cursor or FakeCursor(), session_id=SESSION)


def as_dict(execution) -> dict[str, str]:
    return {row[0]: row[1] for row in execution.static_rows}


# -- the parser serves both capabilities and introspection -------------------


def test_one_parser_recognises_every_dblocker_relation():
    for func in ("context", "queries", "query", "capabilities", "capability"):
        parsed = parse_dblocker_call(f"SELECT * FROM dblocker.{func}('x')", dialect="duckdb")
        assert parsed is not None and parsed.func == func


def test_ordinary_sql_is_not_a_dblocker_call():
    assert parse_dblocker_call("SELECT * FROM analytics.events", dialect="duckdb") is None
    assert parse_dblocker_call("DROP TABLE t", dialect="duckdb") is None


def test_non_literal_arguments_are_refused():
    with pytest.raises(CapabilityError, match="literals"):
        parse_dblocker_call("SELECT * FROM dblocker.query(some_column)", dialect="duckdb")


# -- context() ---------------------------------------------------------------


def test_context_reports_the_pinned_context_and_its_hash(engine):
    execution = call(engine, "SELECT * FROM dblocker.context()")
    values = as_dict(execution)
    assert values["context_hash"] == engine.context.context_hash()
    assert values["catalog"] == "memory"
    assert values["schema"] == "analytics"
    assert values["policy_sha256"] == engine.config.policy_sha256


def test_context_never_reaches_the_downstream(engine):
    cursor = FakeCursor()
    call(engine, "SELECT * FROM dblocker.context()", cursor)
    assert cursor.executed == []


def test_context_exposes_no_credentials(engine):
    execution = call(engine, "SELECT * FROM dblocker.context()")
    assert "password" not in json.dumps(execution.static_rows).lower()


# -- capabilities() ----------------------------------------------------------


def test_capabilities_lists_the_registry_and_what_is_enabled(engine):
    execution = call(engine, "SELECT * FROM dblocker.capabilities()")
    names = [row[0] for row in execution.static_rows]
    assert "describe_table" in names and "row_sample" in names
    enabled = {row[0]: row[2] for row in execution.static_rows}
    assert enabled["describe_table"] is True


# -- queries() and query() ---------------------------------------------------


def test_queries_returns_this_session_s_recent_records(engine):
    with pytest.raises(DeniedError):
        call(engine, "DROP TABLE analytics.events")

    execution = call(engine, "SELECT * FROM dblocker.queries('10')")
    fields = execution.static_fields
    rows = [dict(zip(fields, row, strict=True)) for row in execution.static_rows]
    assert any(r["decision"] == "deny" and r["status"] == "denied" for r in rows)


def test_query_returns_every_event_for_one_id(engine):
    execution = call(engine, "SELECT * FROM analytics.events", FakeCursor())
    query_id = execution.query_id

    looked_up = call(engine, f"SELECT * FROM dblocker.query('{query_id}')")
    fields = looked_up.static_fields
    rows = [dict(zip(fields, row, strict=True)) for row in looked_up.static_rows]
    assert [r["event"] for r in rows] == ["decision", "outcome"]


def test_query_records_carry_no_result_values(engine):
    """Provenance lookups are safe across sessions precisely because of this."""
    call(engine, "SELECT * FROM analytics.events", FakeCursor())
    execution = call(engine, "SELECT * FROM dblocker.queries('10')")
    assert "rows" not in (execution.static_fields or [])


def test_a_bad_limit_is_refused(engine):
    with pytest.raises(DeniedError, match="integer limit"):
        call(engine, "SELECT * FROM dblocker.queries('lots')")
    with pytest.raises(DeniedError, match="between 1 and"):
        call(engine, "SELECT * FROM dblocker.queries('999999')")


def test_an_unknown_relation_is_refused(engine):
    with pytest.raises(DeniedError):
        call(engine, "SELECT * FROM dblocker.nonsense()")


# -- introspection is recorded, but marked as such ---------------------------


def test_introspection_is_recorded_as_introspection(engine):
    call(engine, "SELECT * FROM dblocker.context()")
    records = [
        json.loads(line) for line in engine.evidence.ledger_path.read_text().splitlines() if line
    ]
    assert records[-1]["event"] == "introspection"
    assert records[-1]["relation"] == "context"
