from __future__ import annotations

import pytest

from dblocker.core.bounds import BoundedStream, apply_row_limit


class FakeCursor:
    """Yields rows in batches, recording how many were actually fetched."""

    def __init__(self, rows):
        self._rows = list(rows)
        self.position = 0

    def fetchmany(self, size):
        batch = self._rows[self.position : self.position + size]
        self.position += len(batch)
        return batch


@pytest.mark.parametrize(
    "sql,expected",
    [
        ("SELECT * FROM t", "SELECT * FROM t LIMIT 100"),
        ("SELECT * FROM t LIMIT 999999", "SELECT * FROM t LIMIT 100"),
        ("SELECT * FROM t ORDER BY a", "SELECT * FROM t ORDER BY a LIMIT 100"),
    ],
)
def test_limit_is_injected_or_tightened(sql, expected):
    out, rewritten = apply_row_limit(sql, dialect="duckdb", max_rows=100)
    assert rewritten
    assert out == expected


def test_a_tighter_existing_limit_is_left_alone():
    out, rewritten = apply_row_limit("SELECT * FROM t LIMIT 5", dialect="duckdb", max_rows=100)
    assert not rewritten
    assert out == "SELECT * FROM t LIMIT 5"


def test_unions_and_ctes_are_limited():
    for sql in ("SELECT a FROM t UNION SELECT b FROM u", "WITH c AS (SELECT 1) SELECT * FROM c"):
        out, rewritten = apply_row_limit(sql, dialect="duckdb", max_rows=100)
        assert rewritten and out.endswith("LIMIT 100")


@pytest.mark.parametrize("sql", ["DROP TABLE t", "not valid sql (((", "INSERT INTO t VALUES (1)"])
def test_non_queries_are_never_rewritten(sql):
    out, rewritten = apply_row_limit(sql, dialect="duckdb", max_rows=100)
    assert not rewritten and out == sql


def test_rewriting_is_best_effort_not_the_guarantee():
    """A statement that cannot be rewritten is forwarded unchanged; the row cap
    is still enforced by BoundedStream when the rows are consumed."""
    sql = "not valid sql ((("
    assert apply_row_limit(sql, dialect="duckdb", max_rows=10)[0] == sql
    stream = BoundedStream(max_rows=10, max_bytes=0)
    assert len(list(stream.rows(FakeCursor([(i,) for i in range(500)])))) == 10


def test_stream_stops_at_the_row_cap():
    cursor = FakeCursor([(i,) for i in range(10_000)])
    stream = BoundedStream(max_rows=250, max_bytes=0, batch_size=100)
    rows = list(stream.rows(cursor))
    assert len(rows) == 250
    assert stream.truncated
    # The point of streaming: the whole result was never pulled into memory.
    assert cursor.position < 10_000


def test_stream_stops_at_the_byte_cap():
    cursor = FakeCursor([("x" * 100,) for _ in range(1_000)])
    stream = BoundedStream(max_rows=0, max_bytes=500, batch_size=10)
    list(stream.rows(cursor))
    assert stream.truncated
    assert stream.byte_count >= 500


def test_stream_under_the_cap_is_not_truncated():
    stream = BoundedStream(max_rows=100, max_bytes=0)
    rows = list(stream.rows(FakeCursor([(i,) for i in range(7)])))
    assert len(rows) == 7
    assert not stream.truncated
    assert stream.summary() == {"row_count": 7, "byte_count": stream.byte_count, "truncated": False}


def test_summary_reports_shape_not_values():
    stream = BoundedStream(max_rows=10, max_bytes=0)
    list(stream.rows(FakeCursor([("secret-value",)])))
    assert set(stream.summary()) == {"row_count", "byte_count", "truncated"}
