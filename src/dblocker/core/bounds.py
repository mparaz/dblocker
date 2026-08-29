"""Bounding what a single request can pull back.

Two mechanisms, deliberately layered:

* `apply_row_limit` rewrites a read to carry a `LIMIT`, so the downstream stops
  producing rows early. This is an optimisation -- it is best effort, and any
  statement it cannot rewrite confidently is forwarded untouched.
* `BoundedStream` counts rows and bytes as they are consumed and stops at the
  cap. This is the guarantee, and it holds whether or not the rewrite happened.

The original code called `cursor.fetchall()`, which pulled an entire result set
into proxy memory before anything looked at its size; the extended-protocol row
limit only ever bounded what was *sent* to the client, not what was *fetched*.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError


def apply_row_limit(sql: str, *, dialect: str, max_rows: int) -> tuple[str, bool]:
    """Return (sql, rewritten). Never raises: on any doubt the input is returned
    unchanged and `BoundedStream` enforces the cap instead."""
    if max_rows <= 0:
        return sql, False
    try:
        tree = sqlglot.parse_one(sql, dialect=dialect)
    except ParseError:
        return sql, False
    if tree is None or not isinstance(tree, exp.Query):
        return sql, False

    existing = _existing_limit(tree)
    if existing is not None and existing <= max_rows:
        return sql, False

    try:
        limited = tree.limit(max_rows, copy=True)
        rewritten = limited.sql(dialect=dialect)
        # Cheap sanity check on the round trip: if the regenerated text no
        # longer parses to the same kind of statement, discard the rewrite.
        reparsed = sqlglot.parse_one(rewritten, dialect=dialect)
        if type(reparsed) is not type(tree) and not isinstance(reparsed, exp.Query):
            return sql, False
    except (ParseError, ValueError, TypeError):
        return sql, False
    return rewritten, True


def _existing_limit(tree: exp.Query) -> int | None:
    limit = tree.args.get("limit")
    if limit is None:
        return None
    value = limit.expression if isinstance(limit, exp.Limit) else None
    if isinstance(value, exp.Literal) and not value.is_string:
        try:
            return int(value.this)
        except (TypeError, ValueError):
            return None
    return None


@dataclass
class BoundedStream:
    """Iterates a cursor's rows, stopping at the row or byte cap."""

    max_rows: int
    max_bytes: int
    batch_size: int = 1_000
    row_count: int = 0
    byte_count: int = 0
    truncated: bool = False

    def rows(self, cursor: Any) -> Iterator[list]:
        while True:
            batch = cursor.fetchmany(self.batch_size)
            if not batch:
                return
            for row in batch:
                if self.max_rows > 0 and self.row_count >= self.max_rows:
                    self.truncated = True
                    return
                if self.max_bytes > 0 and self.byte_count >= self.max_bytes:
                    self.truncated = True
                    return
                self.row_count += 1
                self.byte_count += _estimate_bytes(row)
                yield list(row)

    def summary(self) -> dict[str, Any]:
        """Bounded facts about the result -- shape and size, never values."""
        return {
            "row_count": self.row_count,
            "byte_count": self.byte_count,
            "truncated": self.truncated,
        }


def _estimate_bytes(row: Any) -> int:
    total = 0
    for value in row:
        if value is None:
            continue
        if isinstance(value, bytes | bytearray):
            total += len(value)
        elif isinstance(value, str):
            total += len(value)
        else:
            total += len(str(value))
    return total
