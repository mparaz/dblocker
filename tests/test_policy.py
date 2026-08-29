from __future__ import annotations

import pytest

from dblocker.core.classify import analyze
from dblocker.core.config import (
    Config,
    ConfigError,
    ContextConfig,
    DownstreamConfig,
    LimitsConfig,
    ListenConfig,
    Match,
    Rule,
)
from dblocker.core.policy import evaluate


def make_config(rules=None, **overrides) -> Config:
    params = {
        "listen": ListenConfig(),
        "downstream": DownstreamConfig(host="h", port=1, user="u", dbname="d"),
        "context": ContextConfig(catalog="memory", schema="analytics"),
        "limits": LimitsConfig(),
        "rules": rules or [],
    }
    params.update(overrides)
    return Config(**params)


def decide(sql: str, config: Config, capability: str | None = None):
    batch = analyze(
        sql,
        dialect=config.dialect,
        catalog=config.context.catalog,
        schema=config.context.schema,
    )
    return evaluate(batch, sql, config, capability=capability)


READ_ANALYTICS = Rule(
    name="reads",
    action="allow",
    match=Match(statement_class=["read"], all_tables_in={"schemas": ["analytics"]}),
)


def test_default_is_deny():
    assert not decide("SELECT * FROM analytics.events", make_config()).allowed


def test_allow_rule_permits_matching_query():
    config = make_config([READ_ANALYTICS])
    assert decide("SELECT * FROM analytics.events", config).allowed


def test_allow_rule_does_not_cover_other_schemas():
    config = make_config([READ_ANALYTICS])
    assert not decide("SELECT * FROM secure.secrets", config).allowed


def test_allow_rule_does_not_cover_other_statement_classes():
    config = make_config([READ_ANALYTICS])
    assert not decide("DROP TABLE analytics.events", config).allowed


def test_all_tables_in_requires_every_table_to_qualify():
    """A join that reaches one allowed and one disallowed table is refused;
    it is not enough for some table to be in scope."""
    config = make_config([READ_ANALYTICS])
    sql = "SELECT * FROM analytics.events JOIN secure.secrets USING (id)"
    assert not decide(sql, config).allowed


def test_first_matching_rule_wins():
    deny_first = make_config(
        [
            Rule(name="no-events", action="deny", match=Match(tables_match=["*.*.events"])),
            READ_ANALYTICS,
        ]
    )
    decision = decide("SELECT * FROM analytics.events", deny_first)
    assert not decision.allowed and decision.rule_name == "no-events"

    allow_first = make_config(
        [
            READ_ANALYTICS,
            Rule(name="no-events", action="deny", match=Match(tables_match=["*.*.events"])),
        ]
    )
    assert decide("SELECT * FROM analytics.events", allow_first).allowed


def test_reads_external_files_predicate_blocks_table_functions():
    config = make_config(
        [
            Rule(
                name="reads",
                action="allow",
                match=Match(statement_class=["read"], reads_external_files=False),
            )
        ]
    )
    assert decide("SELECT * FROM analytics.events", config).allowed
    assert not decide("SELECT * FROM read_csv_auto('/etc/passwd')", config).allowed


def test_capability_predicate_requires_the_named_capability():
    config = make_config(
        [Rule(name="caps", action="allow", match=Match(capability=["describe_table"]))]
    )
    sql = "SELECT column_name FROM memory.information_schema.columns"
    assert decide(sql, config, capability="describe_table").allowed
    assert not decide(sql, config, capability="row_sample").allowed
    assert not decide(sql, config).allowed


def test_parse_failure_is_denied_before_any_rule_runs():
    permissive = make_config(
        [Rule(name="everything", action="allow", match=Match(statement_class=["unknown"]))]
    )
    decision = decide("not valid sql (((", permissive)
    assert not decision.allowed
    assert "could not be parsed" in decision.reason


def test_multi_statement_batch_is_refused_when_single_statement_only():
    config = make_config([READ_ANALYTICS])
    decision = decide("SELECT * FROM analytics.events; SELECT 1;", config)
    assert not decision.allowed
    assert "single_statement_only" in decision.reason


def test_multi_statement_batch_still_evaluated_per_statement_when_permitted():
    config = make_config([READ_ANALYTICS], limits=LimitsConfig(single_statement_only=False))
    assert decide("SELECT * FROM analytics.events; SELECT * FROM analytics.other;", config).allowed
    assert not decide(
        "SELECT * FROM analytics.events; DROP TABLE analytics.events;", config
    ).allowed


def test_context_switch_is_refused_by_default():
    config = make_config(
        [Rule(name="ctx", action="allow", match=Match(statement_class=["context"]))]
    )
    for sql in ("USE secure", "SET schema = 'secure'", "SET search_path = 'secure'"):
        assert not decide(sql, config).allowed, sql


def test_allowlisted_session_settings_still_pass():
    config = make_config(
        [Rule(name="ctx", action="allow", match=Match(statement_class=["context"]))]
    )
    assert decide("SET extra_float_digits = 3", config).allowed


def test_context_switch_permitted_when_explicitly_enabled():
    config = make_config(
        [Rule(name="ctx", action="allow", match=Match(statement_class=["context"]))],
        context=ContextConfig(catalog="memory", schema="analytics", allow_context_switch=True),
    )
    assert decide("USE secure", config).allowed


def test_permissive_default_requires_explicit_opt_in():
    with pytest.raises(ConfigError, match="allow_permissive_default"):
        make_config(default_action="allow")
    assert make_config(default_action="allow", allow_permissive_default=True).default_action


def test_allow_rule_with_no_predicates_is_rejected():
    with pytest.raises(ConfigError, match="permit everything"):
        Rule(name="oops", action="allow", match=Match())
