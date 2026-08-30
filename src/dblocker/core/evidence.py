"""Durable provenance: what ran, under what policy, against what context.

Two stores, deliberately separated:

* an append-only **JSONL ledger** of provenance records, which carry hashes and
  counts but never SQL text, result values, or downstream error messages;
* a **content-addressed SQL store**, owner-readable only, holding the statement
  text those hashes refer to.

The split is the point. The ledger can be shipped somewhere shared -- to a
reviewer, into a pipeline -- while the SQL text stays with whoever ran it. A
record proves a statement with a given hash was executed; producing the text
for that hash is a separate, local act.

Recording is fail-closed: if a query's decision cannot be written down, the
query does not run. An unrecorded query is worse than a refused one, because it
lets an agent act on data with nothing showing it ever happened.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

LEDGER_VERSION = 1

logger = logging.getLogger("dblocker.evidence")


class LedgerWriteError(OSError):
    """Raised when a provenance record could not be durably written."""


def new_query_id() -> str:
    """A roughly time-sortable identifier.

    48 bits of millisecond timestamp followed by 80 bits of randomness, in the
    same shape as a ULID but hex-encoded to keep it greppable. Ids sort into
    creation order only down to the millisecond; two minted in the same
    millisecond tie-break arbitrarily. The ledger's own append order is the
    authoritative sequence.
    """
    millis = int(time.time() * 1000)
    return f"{millis:012x}{secrets.token_hex(10)}"


def timestamp() -> str:
    return (
        time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        + f".{int(time.time() * 1000) % 1000:03d}Z"
    )


class SqlStore:
    """Content-addressed, write-once storage for statement text."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def prepare(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    def put(self, sql: str) -> tuple[str, str]:
        """Store `sql` and return (sha256, reference).

        The reference is relative to the store root so a ledger record never
        leaks an absolute path from the machine that produced it.
        """
        digest = hashlib.sha256(sql.encode("utf-8")).hexdigest()
        reference = f"{digest[:2]}/{digest}.sql"
        path = self.root / reference
        if path.exists():
            # Content-addressed: identical SQL is already stored, byte for byte.
            return digest, reference
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        # O_EXCL so two threads storing the same statement cannot half-write it.
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return digest, reference
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(sql)
        return digest, reference

    def get(self, digest: str) -> str | None:
        path = self.root / digest[:2] / f"{digest}.sql"
        if not path.exists():
            return None
        return path.read_text(encoding="utf-8")


@dataclass
class EvidenceConfig:
    enabled: bool = True
    ledger_path: Path = Path("var/dblocker/ledger.jsonl")
    sql_store_path: Path = Path("var/dblocker/sql")
    result_digest: bool = True
    on_write_failure: str = "deny"
    ring_buffer_size: int = 1000


class EvidenceLog:
    """Appends provenance records and keeps recent ones queryable in memory."""

    def __init__(self, config: EvidenceConfig) -> None:
        self.config = config
        self.ledger_path = Path(config.ledger_path)
        self.sql_store = SqlStore(config.sql_store_path)
        self._lock = threading.Lock()
        self._recent: deque[dict[str, Any]] = deque(maxlen=max(1, config.ring_buffer_size))
        self._degraded = False

    # -- lifecycle ---------------------------------------------------------

    def prepare(self) -> None:
        """Create and verify the stores. Raises if provenance cannot be kept."""
        if not self.config.enabled:
            return
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self.sql_store.prepare()
        fd = os.open(self.ledger_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.close(fd)
        os.chmod(self.ledger_path, 0o600)

    @property
    def degraded(self) -> bool:
        """True once a record failed to write and could not be made good.

        A query whose rows are already on the wire cannot be un-run, so an
        outcome-write failure cannot be refused retroactively. It instead marks
        the log degraded, and `QueryEngine` refuses subsequent queries while
        that holds -- fail-closed from the next query onwards rather than a
        pretence that the last one was atomic.
        """
        return self._degraded

    def clear_degraded(self) -> None:
        self._degraded = False

    # -- writing -----------------------------------------------------------

    def store_sql(self, sql: str) -> tuple[str, str | None]:
        """Return (sha256, reference). The reference is None when disabled."""
        digest = hashlib.sha256(sql.encode("utf-8")).hexdigest()
        if not self.config.enabled:
            return digest, None
        try:
            return self.sql_store.put(sql)
        except OSError as exc:
            raise LedgerWriteError(f"could not write to the SQL store: {exc}") from exc

    def append(self, record: dict[str, Any], *, critical: bool) -> None:
        """Append one record.

        `critical` marks a record that must exist for the query to be allowed
        to proceed -- the pre-execution decision. Those raise on failure so the
        caller can refuse. Non-critical records (outcomes) cannot un-run a
        query, so they mark the log degraded instead.
        """
        record.setdefault("ledger_version", LEDGER_VERSION)
        record.setdefault("ts", timestamp())
        self._recent.append(record)
        if not self.config.enabled:
            return

        line = json.dumps(record, sort_keys=True, default=str) + "\n"
        try:
            with self._lock:
                fd = os.open(self.ledger_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try:
                    os.write(fd, line.encode("utf-8"))
                    # Provenance that is only in the page cache is not provenance.
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except OSError as exc:
            message = f"could not append to the evidence ledger: {exc}"
            if critical:
                raise LedgerWriteError(message) from exc
            logger.error("%s (ledger is now degraded)", message)
            if self.config.on_write_failure == "deny":
                self._degraded = True

    # -- reading -----------------------------------------------------------

    def recent(self, *, session_id: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        records = list(self._recent)
        if session_id is not None:
            records = [r for r in records if r.get("session_id") == session_id]
        return records[-limit:][::-1]

    def by_id(self, query_id: str) -> list[dict[str, Any]]:
        """All events for one query id, oldest first.

        Not scoped to a session: the records hold no row data, so exposing the
        provenance of another session's query discloses nothing about its
        results.
        """
        return [r for r in self._recent if r.get("query_id") == query_id]
