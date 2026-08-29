from __future__ import annotations

import json
import stat
import time

import pytest

from dblocker.core.evidence import (
    EvidenceConfig,
    EvidenceLog,
    LedgerWriteError,
    SqlStore,
    new_query_id,
)


@pytest.fixture
def log(tmp_path):
    evidence = EvidenceLog(
        EvidenceConfig(
            ledger_path=tmp_path / "ledger.jsonl",
            sql_store_path=tmp_path / "sql",
            ring_buffer_size=5,
        )
    )
    evidence.prepare()
    return evidence


def read_ledger(log: EvidenceLog) -> list[dict]:
    return [json.loads(line) for line in log.ledger_path.read_text().splitlines() if line]


def test_query_ids_are_unique_and_time_ordered_to_the_millisecond():
    ids = [new_query_id() for _ in range(50)]
    assert len(set(ids)) == 50
    # Only the timestamp prefix is ordered; ids minted in the same millisecond
    # tie-break on randomness, and the ledger's append order is authoritative.
    prefixes = [i[:12] for i in ids]
    assert prefixes == sorted(prefixes)


def test_query_ids_sort_across_milliseconds():
    first = new_query_id()
    time.sleep(0.002)
    assert first < new_query_id()


def test_records_are_appended_as_json_lines(log):
    log.append({"event": "decision", "query_id": "a"}, critical=True)
    log.append({"event": "outcome", "query_id": "a"}, critical=False)
    records = read_ledger(log)
    assert [r["event"] for r in records] == ["decision", "outcome"]
    assert all(r["ledger_version"] == 1 and r["ts"] for r in records)


def test_ledger_and_sql_store_are_owner_only(log):
    log.store_sql("SELECT 1")
    assert stat.S_IMODE(log.ledger_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(log.sql_store.root.stat().st_mode) == 0o700
    stored = next(log.sql_store.root.rglob("*.sql"))
    assert stat.S_IMODE(stored.stat().st_mode) == 0o600


def test_sql_store_is_content_addressed_and_write_once(tmp_path):
    store = SqlStore(tmp_path / "sql")
    store.prepare()
    first_digest, first_ref = store.put("SELECT 1")
    second_digest, second_ref = store.put("SELECT 1")
    assert (first_digest, first_ref) == (second_digest, second_ref)
    assert len(list(store.root.rglob("*.sql"))) == 1
    assert store.get(first_digest) == "SELECT 1"
    other_digest, _ = store.put("SELECT 2")
    assert other_digest != first_digest


def test_sql_text_lives_only_in_the_store_never_the_ledger(log):
    digest, ref = log.store_sql("SELECT secret_column FROM analytics.events")
    log.append({"event": "decision", "sql_sha256": digest, "sql_ref": ref}, critical=True)
    ledger_text = log.ledger_path.read_text()
    assert "secret_column" not in ledger_text
    assert digest in ledger_text
    # The text is still recoverable locally, by hash.
    assert "secret_column" in (log.sql_store.get(digest) or "")


def test_a_critical_write_failure_raises(tmp_path):
    evidence = EvidenceLog(
        EvidenceConfig(
            ledger_path=tmp_path / "nope" / "ledger.jsonl",
            sql_store_path=tmp_path / "sql",
        )
    )
    # Never prepared, so the parent directory does not exist.
    with pytest.raises(LedgerWriteError):
        evidence.append({"event": "decision"}, critical=True)


def test_a_non_critical_write_failure_degrades_instead_of_raising(tmp_path):
    evidence = EvidenceLog(
        EvidenceConfig(
            ledger_path=tmp_path / "nope" / "ledger.jsonl",
            sql_store_path=tmp_path / "sql",
        )
    )
    assert not evidence.degraded
    # An outcome cannot un-run a query whose rows already went out, so it marks
    # the log degraded rather than raising; the engine refuses from then on.
    evidence.append({"event": "outcome"}, critical=False)
    assert evidence.degraded
    evidence.clear_degraded()
    assert not evidence.degraded


def test_continue_mode_does_not_degrade(tmp_path):
    evidence = EvidenceLog(
        EvidenceConfig(
            ledger_path=tmp_path / "nope" / "ledger.jsonl",
            sql_store_path=tmp_path / "sql",
            on_write_failure="continue",
        )
    )
    evidence.append({"event": "outcome"}, critical=False)
    assert not evidence.degraded


def test_prepare_refuses_an_unusable_location(tmp_path):
    """dblocker must not start if provenance cannot be written.

    Uses a file where a directory is required rather than permission bits,
    which root ignores.
    """
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("")
    evidence = EvidenceLog(
        EvidenceConfig(ledger_path=blocker / "ledger.jsonl", sql_store_path=tmp_path / "sql")
    )
    with pytest.raises(OSError):
        evidence.prepare()


def test_recent_is_scoped_to_a_session_and_newest_first(log):
    for index in range(3):
        log.append({"query_id": f"q{index}", "session_id": "a"}, critical=False)
    log.append({"query_id": "other", "session_id": "b"}, critical=False)

    recent = log.recent(session_id="a", limit=10)
    assert [r["query_id"] for r in recent] == ["q2", "q1", "q0"]
    assert log.recent(session_id="b", limit=10)[0]["query_id"] == "other"


def test_ring_buffer_evicts_but_the_ledger_keeps_everything(log):
    for index in range(12):  # ring_buffer_size is 5
        log.append({"query_id": f"q{index}", "session_id": "a"}, critical=False)
    assert len(log.recent(session_id="a", limit=100)) == 5
    assert len(read_ledger(log)) == 12


def test_by_id_returns_every_event_for_one_query(log):
    log.append({"event": "decision", "query_id": "q1"}, critical=True)
    log.append({"event": "outcome", "query_id": "q1"}, critical=False)
    log.append({"event": "decision", "query_id": "q2"}, critical=True)
    assert [r["event"] for r in log.by_id("q1")] == ["decision", "outcome"]
    assert log.by_id("missing") == []


def test_disabled_evidence_writes_nothing(tmp_path):
    evidence = EvidenceLog(
        EvidenceConfig(
            enabled=False,
            ledger_path=tmp_path / "ledger.jsonl",
            sql_store_path=tmp_path / "sql",
        )
    )
    evidence.prepare()
    digest, ref = evidence.store_sql("SELECT 1")
    evidence.append({"event": "decision"}, critical=True)
    assert digest and ref is None
    assert not (tmp_path / "ledger.jsonl").exists()
    # Still queryable in memory for the life of the process.
    assert len(evidence.recent(limit=10)) == 1
