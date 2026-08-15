from dblocker.sql_analysis import analyze


def test_unqualified_table_gets_default_catalog_and_schema():
    [parsed] = analyze(
        "SELECT 1 FROM foo", dialect="duckdb", default_catalog="memory", default_schema="main"
    )
    assert parsed.statement_type == "select"
    assert [t.qualified_name for t in parsed.tables] == ["memory.main.foo"]


def test_schema_qualified_table_keeps_default_catalog():
    [parsed] = analyze(
        "SELECT 1 FROM analytics.foo",
        dialect="duckdb",
        default_catalog="memory",
        default_schema="main",
    )
    assert [t.qualified_name for t in parsed.tables] == ["memory.analytics.foo"]


def test_fully_qualified_table():
    [parsed] = analyze(
        "SELECT 1 FROM warehouse.analytics.foo",
        dialect="duckdb",
        default_catalog="memory",
        default_schema="main",
    )
    assert [t.qualified_name for t in parsed.tables] == ["warehouse.analytics.foo"]


def test_cte_alias_is_not_treated_as_a_table():
    [parsed] = analyze(
        "WITH cte AS (SELECT 1 AS x) SELECT * FROM cte",
        dialect="duckdb",
        default_catalog="memory",
        default_schema="main",
    )
    assert parsed.tables == []


def test_join_extracts_all_tables():
    [parsed] = analyze(
        "SELECT * FROM foo JOIN bar ON foo.id = bar.id",
        dialect="duckdb",
        default_catalog="memory",
        default_schema="main",
    )
    assert sorted(t.qualified_name for t in parsed.tables) == [
        "memory.main.bar",
        "memory.main.foo",
    ]


def test_use_statement_sets_schema_only():
    [parsed] = analyze(
        "USE analytics", dialect="duckdb", default_catalog="memory", default_schema="main"
    )
    assert parsed.statement_type == "use"
    assert parsed.sets_schema == "analytics"
    assert parsed.sets_catalog is None
    assert parsed.tables == []


def test_use_statement_sets_catalog_and_schema():
    [parsed] = analyze(
        "USE warehouse.analytics",
        dialect="duckdb",
        default_catalog="memory",
        default_schema="main",
    )
    assert parsed.sets_catalog == "warehouse"
    assert parsed.sets_schema == "analytics"


def test_multi_statement_batch_returns_one_parsed_query_per_statement():
    statements = analyze(
        "SELECT 1 FROM foo; DROP TABLE bar;",
        dialect="duckdb",
        default_catalog="memory",
        default_schema="main",
    )
    assert [s.statement_type for s in statements] == ["select", "drop"]
    assert statements[1].tables[0].qualified_name == "memory.main.bar"


def test_unparseable_sql_is_reported_as_unknown():
    [parsed] = analyze(
        "not even sql (((", dialect="duckdb", default_catalog="memory", default_schema="main"
    )
    assert parsed.statement_type == "unknown"
    assert parsed.parse_error
