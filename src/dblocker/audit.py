"""Structured logging of policy decisions, for building an audit trail."""

from __future__ import annotations

import logging

from dblocker.policy import Decision

logger = logging.getLogger("dblocker.audit")


def record(*, session_id: str, sql: str, decision: Decision) -> None:
    level = logging.INFO if decision.allowed else logging.WARNING
    logger.log(
        level,
        "%s query session=%s rule=%s reason=%s sql=%r",
        "ALLOW" if decision.allowed else "DENY",
        session_id,
        decision.rule_name or "-",
        decision.reason,
        sql,
    )
