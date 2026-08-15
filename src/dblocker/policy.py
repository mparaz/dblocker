"""Evaluates configured rules against a parsed query to allow or deny it."""

from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatch

from dblocker.config import Rule
from dblocker.sql_analysis import ParsedQuery, TableRef


@dataclass
class Decision:
    allowed: bool
    rule_name: str | None
    reason: str


def evaluate(
    statements: list[ParsedQuery],
    raw_sql: str,
    rules: list[Rule],
    default_action: str = "allow",
) -> Decision:
    """Rules are evaluated in order; the first one that matches wins. If no
    rule matches, `default_action` applies."""
    for rule in rules:
        if _matches(rule, statements, raw_sql):
            return Decision(
                allowed=rule.action == "allow", rule_name=rule.name, reason=_reason(rule)
            )
    return Decision(allowed=default_action == "allow", rule_name=None, reason="default action")


def _matches(rule: Rule, statements: list[ParsedQuery], raw_sql: str) -> bool:
    if rule.type == "regex":
        assert rule.pattern is not None  # enforced by Rule.__post_init__
        return re.search(rule.pattern, raw_sql) is not None
    if rule.type == "statement_type_block":
        return any(s.statement_type in rule.statement_types for s in statements)
    if rule.type == "schema_allowlist":
        return any(_outside_allowlist(rule, table) for s in statements for table in s.tables)
    if rule.type == "table_denylist":
        return any(_matches_denylist(rule, table) for s in statements for table in s.tables)
    raise ValueError(f"unknown rule type {rule.type!r}")


def _outside_allowlist(rule: Rule, table: TableRef) -> bool:
    schema_ok = not rule.schemas or table.schema in rule.schemas
    catalog_ok = not rule.catalogs or table.catalog in rule.catalogs
    return not (schema_ok and catalog_ok)


def _matches_denylist(rule: Rule, table: TableRef) -> bool:
    return any(fnmatch(table.qualified_name, pattern) for pattern in rule.tables)


def _reason(rule: Rule) -> str:
    if rule.type == "regex":
        return f"query text matched pattern {rule.pattern!r}"
    if rule.type == "statement_type_block":
        return f"statement type is one of {sorted(rule.statement_types)}"
    if rule.type == "schema_allowlist":
        return "referenced a catalog/schema outside the allowlist"
    if rule.type == "table_denylist":
        return "referenced a table matching a denylisted pattern"
    return "matched"
