"""Deny-by-default policy evaluation.

Rules are evaluated in order and the first whose predicates all hold decides
the query. If no rule matches, `default_action` applies -- normally `deny`.
Polarity lives only in a rule's `action`, so a rule's meaning does not depend
on the name of its predicate.
"""

from __future__ import annotations

import re
from fnmatch import fnmatchcase

from dblocker.core.classify import Analyzed, AnalyzedBatch, StatementClass
from dblocker.core.config import Config, Match, Rule
from dblocker.core.decision import Decision


def evaluate(
    batch: AnalyzedBatch,
    raw_sql: str,
    config: Config,
    *,
    capability: str | None = None,
) -> Decision:
    if config.limits.single_statement_only and batch.statement_count > 1:
        return Decision(
            allowed=False,
            rule_name=None,
            reason=(
                f"request contained {batch.statement_count} statements and "
                "limits.single_statement_only is set"
            ),
        )

    if batch.parse_error:
        return Decision(
            allowed=False,
            rule_name=None,
            reason="statement could not be parsed, so its effect could not be established",
        )

    # A context switch would desynchronise dblocker's view of the effective
    # catalog/schema from the downstream session, which is what policy resolves
    # unqualified names against. Refuse it unless explicitly enabled, allowing
    # only the cosmetic session settings clients need for their handshake.
    if not config.context.allow_context_switch:
        for statement in batch.statements:
            if statement.cls is not StatementClass.CONTEXT:
                continue
            disallowed = _disallowed_settings(statement, config)
            if statement.sets_schema or statement.sets_catalog or disallowed:
                return Decision(
                    allowed=False,
                    rule_name=None,
                    reason=(
                        "statement changes the session context "
                        f"({disallowed or 'catalog/schema'}) and "
                        "context.allow_context_switch is false"
                    ),
                )

    for rule in config.rules:
        if _rule_matches(rule, batch, raw_sql, capability):
            return Decision(
                allowed=rule.action == "allow",
                rule_name=rule.name,
                reason=_describe(rule),
            )

    return Decision(
        allowed=config.default_action == "allow",
        rule_name=None,
        reason=f"no rule matched; default_action is {config.default_action}",
    )


def _disallowed_settings(statement: Analyzed, config: Config) -> str:
    allowed = set(config.context.session_settings_allowlist)
    offenders = [name for name in statement.setting_names if name not in allowed]
    return ", ".join(sorted(offenders))


def _rule_matches(rule: Rule, batch: AnalyzedBatch, raw_sql: str, capability: str | None) -> bool:
    match = rule.match
    if match.is_empty:
        return True
    if not _sql_level_matches(match, raw_sql, capability):
        return False
    # Every statement in the request must satisfy the statement-level
    # predicates; a batch is only as permitted as its least permitted statement.
    return all(_statement_matches(match, statement) for statement in batch.statements)


def _sql_level_matches(match: Match, raw_sql: str, capability: str | None) -> bool:
    if match.regex is not None and re.search(match.regex, raw_sql) is None:
        return False
    if match.not_regex is not None and re.search(match.not_regex, raw_sql) is not None:
        return False
    if match.capability is not None and (capability or "").lower() not in match.capability:
        return False
    return True


def _statement_matches(match: Match, statement: Analyzed) -> bool:
    if match.statement_class is not None and statement.cls.value not in match.statement_class:
        return False
    if match.reads_external_files is not None:
        if statement.reads_external_files != match.reads_external_files:
            return False
    if match.writes_external_files is not None:
        if statement.writes_external_files != match.writes_external_files:
            return False
    if match.all_tables_in is not None and not _all_tables_in(match, statement):
        return False
    if match.tables_match is not None and not _every_table_matches(match.tables_match, statement):
        return False
    if match.tables_not_match is not None and _any_table_matches(match.tables_not_match, statement):
        return False
    return True


def _all_tables_in(match: Match, statement: Analyzed) -> bool:
    scope = match.all_tables_in or {}
    catalogs = scope.get("catalogs")
    schemas = scope.get("schemas")
    for table in statement.tables:
        if catalogs is not None and table.catalog not in catalogs:
            return False
        if schemas is not None and table.schema not in schemas:
            return False
    return True


def _every_table_matches(patterns: list[str], statement: Analyzed) -> bool:
    return all(
        any(fnmatchcase(table.qualified_name, pattern) for pattern in patterns)
        for table in statement.tables
    )


def _any_table_matches(patterns: list[str], statement: Analyzed) -> bool:
    return any(
        fnmatchcase(table.qualified_name, pattern)
        for table in statement.tables
        for pattern in patterns
    )


def _describe(rule: Rule) -> str:
    if rule.action == "allow":
        return f"permitted by rule {rule.name!r}"
    return f"refused by rule {rule.name!r}"
