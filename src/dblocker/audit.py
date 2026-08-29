"""Structured logging of policy decisions.

Records are emitted as JSON so they can be collected mechanically, and they
carry `sql_sha256` rather than the statement text. That is a deliberate
constraint borrowed from the durable-provenance model this will grow into: a
record should be safe to ship somewhere shared, while the SQL it refers to
stays with its owner. Result rows are never recorded at all.
"""

from __future__ import annotations

import json
import logging

from dblocker.core.decision import DecisionRecord

logger = logging.getLogger("dblocker.audit")


def record_decision(record: DecisionRecord) -> None:
    level = logging.INFO if record.decision == "allow" else logging.WARNING
    logger.log(level, "%s", json.dumps(record.as_dict(), sort_keys=True, default=str))
