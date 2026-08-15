from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from dblocker.config import Rule
from dblocker.proxy_backend import PolicySession, PolicyViolation


def make_session(rules, default_action="allow"):
    cursor = MagicMock()
    cursor.statusmessage = "SELECT 1"
    cursor.description = None
    conn = MagicMock()
    conn.cursor.return_value = cursor

    parent = SimpleNamespace(
        dialect="duckdb",
        default_catalog="memory",
        default_schema="main",
        rules=rules,
        default_action=default_action,
    )
    return PolicySession(parent, conn), cursor


def test_allowed_query_is_forwarded_to_downstream():
    session, cursor = make_session(rules=[])
    session.execute_sql("SELECT 1 FROM main.foo")
    cursor.execute.assert_called_once_with("SELECT 1 FROM main.foo")


def test_denied_query_is_not_forwarded():
    rule = Rule(name="deny-foo", type="table_denylist", action="deny", tables=["*.*.foo"])
    session, cursor = make_session(rules=[rule])
    with pytest.raises(PolicyViolation):
        session.execute_sql("SELECT 1 FROM main.foo")
    cursor.execute.assert_not_called()


def test_default_deny_blocks_unmatched_queries():
    session, cursor = make_session(rules=[], default_action="deny")
    with pytest.raises(PolicyViolation):
        session.execute_sql("SELECT 1 FROM main.foo")
    cursor.execute.assert_not_called()


def test_use_statement_updates_session_context_after_forwarding():
    session, cursor = make_session(rules=[])
    session.execute_sql("USE analytics")
    assert session.current_schema == "analytics"
    cursor.execute.assert_called_once_with("USE analytics")


def test_use_statement_context_is_not_updated_if_denied():
    rule = Rule(name="no-use", type="statement_type_block", action="deny", statement_types=["use"])
    session, cursor = make_session(rules=[rule])
    with pytest.raises(PolicyViolation):
        session.execute_sql("USE analytics")
    assert session.current_schema == "main"
    cursor.execute.assert_not_called()


def test_schema_allowlist_blocks_query_after_use_switches_context():
    rule = Rule(name="only-main", type="schema_allowlist", action="deny", schemas=["main"])
    session, cursor = make_session(rules=[rule])

    session.execute_sql("USE analytics")
    assert session.current_schema == "analytics"

    with pytest.raises(PolicyViolation):
        session.execute_sql("SELECT 1 FROM foo")
    cursor.execute.assert_called_once_with("USE analytics")
