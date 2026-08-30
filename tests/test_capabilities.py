from __future__ import annotations

import pytest

from dblocker.core.capabilities import (
    REGISTRY,
    CapabilityError,
    parse_capability_call,
    render,
)
from dblocker.core.classify import analyze
from dblocker.core.context import SessionContext
from dblocker.core.policy import evaluate

ALL = sorted(REGISTRY)


@pytest.fixture
def context():
    return SessionContext(
        downstream_host="localhost",
        downstream_port=5433,
        downstream_user="u",
        downstream_dbname="memory",
        catalog="memory",
        schema="analytics",
        dialect="duckdb",
        policy_sha256="p",
    )


def call(sql: str):
    return parse_capability_call(sql, dialect="duckdb")


def test_ordinary_sql_is_not_a_capability_call():
    assert call("SELECT * FROM analytics.events") is None
    assert call("DROP TABLE t") is None


def test_every_registered_capability_renders(context):
    args = {
        "list_schemas": "",
        "list_tables": ", 'analytics'",
        "describe_table": ", 'analytics.events'",
        "table_row_count": ", 'events'",
        "column_stats": ", 'analytics.events', 'id'",
        "row_sample": ", 'analytics.events', '5'",
    }
    for name in ALL:
        parsed = call(f"SELECT * FROM dblocker.capability('{name}'{args[name]})")
        sql = render(parsed, context=context, enabled=ALL)
        assert sql.lower().startswith("select")


def test_unqualified_target_resolves_against_the_pinned_context(context):
    sql = render(
        call("SELECT * FROM dblocker.capability('table_row_count','events')"),
        context=context,
        enabled=ALL,
    )
    assert "memory.analytics.events" in sql


@pytest.mark.parametrize(
    "target",
    [
        "a'; DROP TABLE x--",
        "analytics.events; DROP TABLE x",
        "analytics.events WHERE 1=1",
        "a.b.c.d",
        "",
        "*",
        "../../etc/passwd",
        "events UNION SELECT * FROM secure.secrets",
    ],
)
def test_malicious_targets_are_refused(context, target):
    """Refusal may happen at parse (the argument is not a literal) or at render
    (the literal is not a plain identifier); either is a refusal."""
    literal = target.replace("'", "''")
    sql = f"SELECT * FROM dblocker.capability('row_sample', '{literal}')"
    with pytest.raises((CapabilityError, ValueError)):
        parsed = call(sql)
        if parsed is None:
            raise CapabilityError("not recognised as a capability call")
        render(parsed, context=context, enabled=ALL)


def test_malicious_column_argument_is_refused(context):
    parsed = call(
        "SELECT * FROM dblocker.capability('column_stats','analytics.events','id) FROM x--')"
    )
    with pytest.raises((CapabilityError, ValueError)):
        render(parsed, context=context, enabled=ALL)


def test_non_literal_arguments_are_refused():
    with pytest.raises(CapabilityError, match="literals"):
        call("SELECT * FROM dblocker.capability(some_column)")


def test_row_sample_size_is_bounded(context):
    with pytest.raises(CapabilityError, match="between 1 and"):
        render(
            call("SELECT * FROM dblocker.capability('row_sample','analytics.events','999999')"),
            context=context,
            enabled=ALL,
        )


def test_arity_is_enforced(context):
    with pytest.raises(CapabilityError, match="argument"):
        render(
            call("SELECT * FROM dblocker.capability('list_schemas','extra')"),
            context=context,
            enabled=ALL,
        )


def test_unknown_and_disabled_capabilities_are_refused(context):
    with pytest.raises(CapabilityError, match="unknown capability"):
        render(call("SELECT * FROM dblocker.capability('nope')"), context=context, enabled=ALL)
    with pytest.raises(CapabilityError, match="not enabled"):
        render(
            call("SELECT * FROM dblocker.capability('row_sample','analytics.events')"),
            context=context,
            enabled=[],
        )


def test_naming_a_capability_does_not_widen_reach(context, example_config):
    """A capability targeting a table outside the allowed scope renders a read
    of that table, which the ordinary rules then refuse."""
    rendered = render(
        call("SELECT * FROM dblocker.capability('row_sample','secure.secrets')"),
        context=context,
        enabled=ALL,
    )
    batch = analyze(rendered, dialect="duckdb", catalog="memory", schema="analytics")
    decision = evaluate(batch, rendered, example_config, capability="row_sample")
    assert not decision.allowed


def test_in_scope_capability_target_is_allowed(context, example_config):
    rendered = render(
        call("SELECT * FROM dblocker.capability('row_sample','analytics.events')"),
        context=context,
        enabled=ALL,
    )
    batch = analyze(rendered, dialect="duckdb", catalog="memory", schema="analytics")
    assert evaluate(batch, rendered, example_config, capability="row_sample").allowed


def test_metadata_capability_is_allowed_by_the_example_policy(context, example_config):
    rendered = render(
        call("SELECT * FROM dblocker.capability('describe_table','analytics.events')"),
        context=context,
        enabled=ALL,
    )
    batch = analyze(rendered, dialect="duckdb", catalog="memory", schema="analytics")
    assert evaluate(batch, rendered, example_config, capability="describe_table").allowed
