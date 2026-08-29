from __future__ import annotations

import pytest

from dblocker.core.classify import StatementClass, analyze

DIALECT = "duckdb"


def one(sql: str, *, catalog: str = "memory", schema: str = "main"):
    batch = analyze(sql, dialect=DIALECT, catalog=catalog, schema=schema)
    assert batch.statement_count == 1
    return batch.statements[0]


@pytest.mark.parametrize(
    "sql,expected",
    [
        ("SELECT 1", StatementClass.READ),
        ("SELECT a FROM t UNION SELECT b FROM u", StatementClass.READ),
        ("VALUES (1)", StatementClass.READ),
        ("SHOW TABLES", StatementClass.READ),
        ("DESCRIBE t", StatementClass.READ),
        ("SUMMARIZE t", StatementClass.READ),
        ("INSERT INTO t VALUES (1)", StatementClass.WRITE),
        ("UPDATE t SET a = 1", StatementClass.WRITE),
        ("DELETE FROM t", StatementClass.WRITE),
        ("CREATE TABLE t (a INT)", StatementClass.DDL),
        ("DROP TABLE t", StatementClass.DDL),
        ("ALTER TABLE t ADD COLUMN b INT", StatementClass.DDL),
        ("TRUNCATE TABLE t", StatementClass.DDL),
        ("ATTACH 'x.duckdb' AS x", StatementClass.ADMIN),
        ("DETACH x", StatementClass.ADMIN),
        ("INSTALL httpfs", StatementClass.ADMIN),
        ("COPY t TO '/tmp/x.csv'", StatementClass.ADMIN),
        ("PRAGMA database_list", StatementClass.ADMIN),
        ("USE x", StatementClass.CONTEXT),
        ("SET schema = 'x'", StatementClass.CONTEXT),
        ("BEGIN", StatementClass.TRANSACTION),
        ("COMMIT", StatementClass.TRANSACTION),
        ("ROLLBACK", StatementClass.TRANSACTION),
    ],
)
def test_statement_classes(sql, expected):
    assert one(sql).cls is expected


@pytest.mark.parametrize(
    "sql",
    [
        "not valid sql (((",
        "LOAD httpfs",
        "CALL some_procedure()",
        "EXPORT DATABASE '/tmp/dump'",
        "CREATE SECRET s (TYPE S3)",
    ],
)
def test_unmodelled_syntax_is_unknown(sql):
    """Anything whose effect cannot be established must classify as UNKNOWN so
    that no allow rule can ever match it."""
    assert one(sql).cls is StatementClass.UNKNOWN


def test_parse_error_is_flagged_and_unknown():
    batch = analyze("not valid sql (((", dialect=DIALECT, catalog="memory", schema="main")
    assert batch.parse_error
    assert batch.statements[0].cls is StatementClass.UNKNOWN


def test_explain_inherits_the_class_of_its_inner_statement():
    assert one("EXPLAIN SELECT * FROM t").cls is StatementClass.READ
    # EXPLAIN ANALYZE actually runs the statement, so it must not inherit READ.
    assert one("EXPLAIN ANALYZE DELETE FROM t").cls is StatementClass.UNKNOWN


def test_explain_exposes_the_inner_tables():
    assert [t.qualified_name for t in one("EXPLAIN SELECT * FROM t").tables] == ["memory.main.t"]


def test_unqualified_names_resolve_against_the_pinned_context():
    stmt = one("SELECT * FROM events", catalog="warehouse", schema="analytics")
    assert [t.qualified_name for t in stmt.tables] == ["warehouse.analytics.events"]


def test_cte_alias_is_not_a_table_reference():
    assert one("WITH c AS (SELECT 1) SELECT * FROM c").tables == []


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM read_csv_auto('/etc/passwd')",
        "SELECT * FROM read_parquet('s3://b/x.parquet')",
        "SELECT * FROM glob('/**')",
        "SELECT * FROM parquet_scan('/x.parquet')",
    ],
)
def test_file_reading_table_functions_are_flagged(sql):
    stmt = one(sql)
    assert stmt.reads_external_files
    # They name no table, which is exactly why a table-based allowlist missed them.
    assert stmt.tables == []


def test_copy_direction_is_recorded():
    to_file = one("COPY t TO '/tmp/x.csv'")
    assert to_file.writes_external_files and not to_file.reads_external_files
    from_file = one("COPY t FROM '/tmp/x.csv'")
    assert from_file.reads_external_files and not from_file.writes_external_files


def test_set_records_setting_names_and_schema_changes():
    assert one("SET extra_float_digits = 3").setting_names == ["extra_float_digits"]
    assert one("SET search_path = 'secure'").sets_schema == "secure"
    assert one("SET schema = 'secure'").sets_schema == "secure"


def test_use_tracks_catalog_and_schema():
    assert one("USE analytics").sets_schema == "analytics"
    qualified = one("USE warehouse.analytics")
    assert (qualified.sets_catalog, qualified.sets_schema) == ("warehouse", "analytics")


def test_use_kind_recovery_is_duckdb_only():
    """sqlglot's generic USE grammar swallows some leading identifiers as a
    `kind` keyword. Recovering it as a catalog is right for DuckDB but wrong
    for Snowflake, where `USE ROLE x` genuinely selects a role."""
    duck = analyze("USE warehouse.analytics", dialect="duckdb", catalog="c", schema="s")
    assert duck.statements[0].sets_catalog == "warehouse"
    snow = analyze("USE warehouse.analytics", dialect="snowflake", catalog="c", schema="s")
    assert snow.statements[0].sets_catalog is None


def test_multi_statement_batches_are_split():
    batch = analyze(
        "SELECT * FROM t; DROP TABLE t;", dialect=DIALECT, catalog="memory", schema="main"
    )
    assert [s.cls for s in batch.statements] == [StatementClass.READ, StatementClass.DDL]
