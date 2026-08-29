from __future__ import annotations

import json

import pytest
from corpus import MUST_ALLOW, MUST_DENY

from dblocker.core.config import load_config
from dblocker.core.context import SessionContext
from dblocker.core.engine import DeniedError, QueryEngine
from dblocker.core.evidence import EvidenceConfig, EvidenceLog

SESSION = "test-session"


class FakeCursor:
    """A cursor whose rows and failure mode the test chooses."""

    def __init__(self, rows=None, description=None, error=None):
        self._rows = list(rows or [])
        self.description = description
        self.error = error
        self.statusmessage = "SELECT"
        self.executed: list[str] = []
        self.position = 0

    def execute(self, sql, params=None):
        self.executed.append(sql)
        if self.error is not None:
            raise self.error

    def fetchmany(self, size):
        batch = self._rows[self.position : self.position + size]
        self.position += len(batch)
        return batch


class Boom(Exception):
    sqlstate = "42P01"


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


def ledger(engine) -> list[dict]:
    path = engine.evidence.ledger_path
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def rows_cursor(rows=None):
    return FakeCursor(rows=rows or [(1, "a")], description=[("id", 23), ("name", 25)])


# -- the refactor must not have changed a single verdict ---------------------


@pytest.mark.parametrize("sql,why", MUST_DENY, ids=[s for s, _ in MUST_DENY])
def test_bypasses_are_still_denied_through_the_engine(engine, sql, why):
    with pytest.raises(DeniedError):
        engine.execute(sql, cursor=rows_cursor(), session_id=SESSION)


@pytest.mark.parametrize("sql,why", MUST_ALLOW, ids=[s for s, _ in MUST_ALLOW])
def test_legitimate_queries_still_run_through_the_engine(engine, sql, why):
    cursor = rows_cursor()
    execution = engine.execute(sql, cursor=cursor, session_id=SESSION)
    assert execution.decision.allowed
    assert cursor.executed, "an allowed query must reach the downstream"


# -- lifecycle ---------------------------------------------------------------


def test_an_allowed_query_writes_a_decision_then_an_outcome(engine):
    cursor = rows_cursor([(1, "a"), (2, "b")])
    execution = engine.execute("SELECT * FROM analytics.events", cursor=cursor, session_id=SESSION)
    list(execution.rows)  # consuming the stream completes the lifecycle

    records = ledger(engine)
    assert [r["event"] for r in records] == ["decision", "outcome"]
    assert {r["query_id"] for r in records} == {execution.query_id}
    assert records[0]["decision"] == "allow"
    assert records[1]["status"] == "succeeded"
    assert records[1]["row_count"] == 2
    assert records[1]["result_sha256"]


def test_a_denied_query_writes_one_terminal_record_and_never_executes(engine):
    cursor = rows_cursor()
    with pytest.raises(DeniedError):
        engine.execute("DROP TABLE analytics.events", cursor=cursor, session_id=SESSION)

    records = ledger(engine)
    assert len(records) == 1
    assert records[0]["event"] == "decision"
    assert records[0]["decision"] == "deny"
    assert records[0]["status"] == "denied"
    assert cursor.executed == []


def test_truncation_is_recorded(engine):
    engine.config.limits.max_rows = 3
    cursor = rows_cursor([(i, "x") for i in range(100)])
    execution = engine.execute("SELECT * FROM analytics.events", cursor=cursor, session_id=SESSION)
    assert len(list(execution.rows)) == 3
    outcome = ledger(engine)[-1]
    assert outcome["status"] == "truncated"
    assert outcome["truncated"] is True
    assert outcome["row_count"] == 3


def test_a_downstream_failure_records_the_error_class_not_its_message(engine):
    cursor = FakeCursor(error=Boom('relation "events" does not exist: secret-value'))
    with pytest.raises(Boom):
        engine.execute("SELECT * FROM analytics.events", cursor=cursor, session_id=SESSION)

    outcome = ledger(engine)[-1]
    assert outcome["event"] == "outcome"
    assert outcome["status"] == "failed"
    assert outcome["error_class"] == "Boom/42P01"
    # Downstream error text can quote row values, so none of it is recorded.
    assert "secret-value" not in json.dumps(outcome)


def test_an_abandoned_result_still_records_an_outcome(engine):
    """A client that disconnects mid-stream must not leave a query unaccounted."""
    cursor = rows_cursor([(i, "x") for i in range(100)])
    execution = engine.execute("SELECT * FROM analytics.events", cursor=cursor, session_id=SESSION)
    next(iter(execution.rows))
    execution.stream.finalize()
    assert ledger(engine)[-1]["event"] == "outcome"


# -- fail-closed -------------------------------------------------------------


def test_a_query_is_refused_when_its_decision_cannot_be_recorded(engine, tmp_path):
    engine.evidence.ledger_path = tmp_path / "gone" / "ledger.jsonl"
    cursor = rows_cursor()
    with pytest.raises(DeniedError, match="provenance could not be recorded"):
        engine.execute("SELECT * FROM analytics.events", cursor=cursor, session_id=SESSION)
    assert cursor.executed == [], "nothing may run that cannot be recorded"


def test_a_degraded_ledger_refuses_subsequent_queries(engine):
    engine.evidence._degraded = True
    with pytest.raises(DeniedError, match="degraded"):
        engine.execute("SELECT * FROM analytics.events", cursor=rows_cursor(), session_id=SESSION)


# -- provenance content ------------------------------------------------------


def test_the_ledger_records_hashes_not_sql_text(engine):
    sql = "SELECT * FROM analytics.events WHERE name = 'distinctive-literal'"
    execution = engine.execute(sql, cursor=rows_cursor(), session_id=SESSION)
    list(execution.rows)

    text = engine.evidence.ledger_path.read_text()
    assert "distinctive-literal" not in text
    assert execution.sql_sha256 in text
    # The statement itself is still recoverable locally, by hash.
    assert "distinctive-literal" in (engine.evidence.sql_store.get(execution.sql_sha256) or "")


def test_the_canonical_sql_is_recorded_separately_when_bounded(engine):
    execution = engine.execute(
        "SELECT * FROM analytics.events", cursor=rows_cursor(), session_id=SESSION
    )
    assert execution.canonical_sql.endswith(f"LIMIT {engine.config.limits.max_rows}")
    # What was asked and what actually ran are both attested.
    assert execution.sql_sha256 != execution.canonical_sql_sha256
    decision = ledger(engine)[0]
    assert decision["sql_sha256"] != decision["canonical_sql_sha256"]
    assert engine.evidence.sql_store.get(decision["canonical_sql_sha256"])


def test_capability_arguments_are_never_spliced_into_sql(engine):
    """The structured entry point takes values, so there is no text to escape."""
    with pytest.raises(DeniedError):
        engine.execute_capability(
            "row_sample",
            ["analytics.events'); DROP TABLE x--"],
            cursor=rows_cursor(),
            session_id=SESSION,
        )


def test_capability_cannot_reach_outside_the_allowed_scope(engine):
    with pytest.raises(DeniedError):
        engine.execute_capability(
            "row_sample", ["secure.secrets"], cursor=rows_cursor(), session_id=SESSION
        )


def test_capability_records_its_name(engine):
    execution = engine.execute_capability(
        "row_sample", ["analytics.events"], cursor=rows_cursor(), session_id=SESSION
    )
    list(execution.rows)
    assert ledger(engine)[0]["capability"] == "row_sample"
    assert execution.evidence()["capability"] == "row_sample"


def test_a_result_cut_by_the_injected_limit_is_reported_as_truncated(engine):
    """The subtle case: dblocker's own LIMIT stops the downstream first.

    The stream then ends naturally without hitting its cap, so nothing in it
    looks truncated -- but the caller did not get the whole result, and a
    record claiming otherwise would mislead whoever reads it later.
    """
    engine.config.limits.max_rows = 10
    # The downstream honours the injected LIMIT, so exactly max_rows come back.
    cursor = rows_cursor([(i, "x") for i in range(10)])
    execution = engine.execute("SELECT * FROM analytics.events", cursor=cursor, session_id=SESSION)
    assert len(list(execution.rows)) == 10
    assert not execution.stream.truncated, "the stream itself never hit its cap"

    outcome = ledger(engine)[-1]
    assert outcome["row_limit_applied"] is True
    assert outcome["truncated"] is True
    assert outcome["status"] == "truncated"
    assert execution.evidence()["truncated"] is True


def test_a_short_result_is_not_falsely_marked_truncated(engine):
    engine.config.limits.max_rows = 10
    execution = engine.execute(
        "SELECT * FROM analytics.events",
        cursor=rows_cursor([(1, "a"), (2, "b")]),
        session_id=SESSION,
    )
    list(execution.rows)
    outcome = ledger(engine)[-1]
    assert outcome["truncated"] is False
    assert outcome["status"] == "succeeded"
    assert execution.evidence()["truncated"] is False


def test_a_users_own_smaller_limit_is_not_reported_as_truncation(engine):
    """dblocker did not cut this one; the caller asked for exactly that many."""
    engine.config.limits.max_rows = 100
    execution = engine.execute(
        "SELECT * FROM analytics.events LIMIT 2",
        cursor=rows_cursor([(1, "a"), (2, "b")]),
        session_id=SESSION,
    )
    list(execution.rows)
    outcome = ledger(engine)[-1]
    assert outcome["row_limit_applied"] is False
    assert outcome["truncated"] is False
