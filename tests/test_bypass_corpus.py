"""Regression net for the bypasses found reviewing the first implementation.

Every statement in `MUST_DENY` was **allowed** by the original table-reference
allowlist. They are kept here verbatim as the standing proof that dblocker
fails closed: a statement whose effect cannot be established, or that reaches
data by a route other than a table reference, must never be forwarded.
"""

from __future__ import annotations

import pytest
from corpus import MUST_ALLOW, MUST_DENY

from dblocker.core.classify import analyze
from dblocker.core.policy import evaluate


def decide(sql: str, config):
    batch = analyze(
        sql,
        dialect=config.dialect,
        catalog=config.context.catalog,
        schema=config.context.schema,
    )
    return evaluate(batch, sql, config)


@pytest.mark.parametrize("sql,why", MUST_DENY, ids=[s for s, _ in MUST_DENY])
def test_bypass_is_denied(sql, why, example_config):
    decision = decide(sql, example_config)
    assert not decision.allowed, f"{sql!r} was allowed but {why}"


@pytest.mark.parametrize("sql,why", MUST_ALLOW, ids=[s for s, _ in MUST_ALLOW])
def test_legitimate_query_is_allowed(sql, why, example_config):
    decision = decide(sql, example_config)
    assert decision.allowed, f"{sql!r} was denied but it is {why} (reason: {decision.reason})"


def test_denial_carries_a_machine_readable_sqlstate(example_config):
    decision = decide("DROP TABLE analytics.events", example_config)
    assert not decision.allowed
    # 42501 = insufficient_privilege; lets an agent distinguish a policy refusal
    # from a syntax error without parsing the message text.
    assert decision.sqlstate == "42501"
    assert "dblocker denied" in decision.message()
