from dblocker.config import Rule
from dblocker.policy import evaluate
from dblocker.sql_analysis import ParsedQuery, TableRef


def stmt(catalog="memory", schema="main", name="foo", statement_type="select"):
    return ParsedQuery(
        statement_type=statement_type,
        tables=[TableRef(catalog, schema, name)],
    )


def test_default_action_when_no_rules_match():
    decision = evaluate([stmt()], "SELECT 1 FROM foo", rules=[], default_action="allow")
    assert decision.allowed
    assert decision.rule_name is None


def test_default_action_deny_when_configured():
    decision = evaluate([stmt()], "SELECT 1 FROM foo", rules=[], default_action="deny")
    assert not decision.allowed


def test_schema_allowlist_denies_outside_schema():
    rule = Rule(
        name="only-analytics", type="schema_allowlist", action="deny", schemas=["analytics"]
    )
    decision = evaluate([stmt(schema="main")], "SELECT 1 FROM main.foo", rules=[rule])
    assert not decision.allowed
    assert decision.rule_name == "only-analytics"


def test_schema_allowlist_allows_listed_schema():
    rule = Rule(
        name="only-analytics", type="schema_allowlist", action="deny", schemas=["analytics"]
    )
    decision = evaluate([stmt(schema="analytics")], "SELECT 1 FROM analytics.foo", rules=[rule])
    assert decision.allowed


def test_schema_allowlist_checks_catalog_too():
    rule = Rule(
        name="only-warehouse", type="schema_allowlist", action="deny", catalogs=["warehouse"]
    )
    denied = evaluate([stmt(catalog="memory")], "SELECT 1 FROM foo", rules=[rule])
    allowed = evaluate([stmt(catalog="warehouse")], "SELECT 1 FROM foo", rules=[rule])
    assert not denied.allowed
    assert allowed.allowed


def test_table_denylist_matches_glob():
    rule = Rule(name="no-tmp", type="table_denylist", action="deny", tables=["*.*.tmp_*"])
    decision = evaluate([stmt(name="tmp_scratch")], "SELECT 1 FROM tmp_scratch", rules=[rule])
    assert not decision.allowed


def test_table_denylist_does_not_match_other_tables():
    rule = Rule(name="no-tmp", type="table_denylist", action="deny", tables=["*.*.tmp_*"])
    decision = evaluate([stmt(name="real_table")], "SELECT 1 FROM real_table", rules=[rule])
    assert decision.allowed


def test_statement_type_block():
    rule = Rule(name="no-ddl", type="statement_type_block", action="deny", statement_types=["drop"])
    decision = evaluate([stmt(statement_type="drop")], "DROP TABLE foo", rules=[rule])
    assert not decision.allowed


def test_regex_rule_matches_raw_sql():
    rule = Rule(name="no-pg-catalog", type="regex", action="deny", pattern=r"pg_catalog\.")
    decision = evaluate([stmt()], "SELECT * FROM pg_catalog.pg_tables", rules=[rule])
    assert not decision.allowed


def test_regex_rule_does_not_match_unrelated_sql():
    rule = Rule(name="no-pg-catalog", type="regex", action="deny", pattern=r"pg_catalog\.")
    decision = evaluate([stmt()], "SELECT 1 FROM foo", rules=[rule])
    assert decision.allowed


def test_first_matching_rule_wins():
    ddl_stmt = stmt(schema="other", statement_type="drop")
    rule_ddl = Rule(
        name="no-ddl", type="statement_type_block", action="deny", statement_types=["drop"]
    )
    rule_schema = Rule(name="only-main", type="schema_allowlist", action="deny", schemas=["main"])

    first = evaluate([ddl_stmt], "DROP TABLE other.foo", rules=[rule_ddl, rule_schema])
    assert first.rule_name == "no-ddl"

    second = evaluate([ddl_stmt], "DROP TABLE other.foo", rules=[rule_schema, rule_ddl])
    assert second.rule_name == "only-main"


def test_batch_is_denied_if_any_statement_violates_a_rule():
    rule = Rule(name="no-ddl", type="statement_type_block", action="deny", statement_types=["drop"])
    statements = [stmt(statement_type="select"), stmt(statement_type="drop")]
    decision = evaluate(statements, "SELECT 1 FROM foo; DROP TABLE foo;", rules=[rule])
    assert not decision.allowed
