"""The statements that defeated dblocker's first table-reference allowlist.

Kept in one place because two suites assert against them: `test_bypass_corpus`
checks the policy engine's verdicts directly, and `test_engine` checks the same
verdicts survive the whole execution path. A new evasion route belongs here
first.
"""

from __future__ import annotations

# Each entry is (sql, why_it_matters).
MUST_DENY = [
    # Attaching another database sidesteps a catalog/schema allowlist entirely.
    ("ATTACH 'evil.duckdb' AS evil", "attaches an unvetted database"),
    ("ATTACH 'https://evil.example/x.duckdb' AS evil (READ_ONLY)", "attaches a remote database"),
    ("DETACH analytics", "detaches a database"),
    # Writing query output to the local filesystem is exfiltration.
    ("COPY (SELECT * FROM analytics.events) TO '/tmp/exfil.csv'", "writes results to disk"),
    ("COPY analytics.events TO '/tmp/exfil.parquet'", "writes a table to disk"),
    ("EXPORT DATABASE '/tmp/dump'", "dumps the whole database"),
    # Extension loading enables network egress.
    ("INSTALL httpfs", "installs an extension"),
    ("LOAD httpfs", "loads an extension"),
    # Table functions read data without ever naming a table.
    ("SELECT * FROM read_csv_auto('/etc/passwd')", "reads an arbitrary local file"),
    ("SELECT * FROM read_parquet('s3://bucket/x.parquet')", "reads remote object storage"),
    ("SELECT * FROM glob('/**')", "enumerates the filesystem"),
    # Context switches desynchronise policy from the downstream session.
    ("SET schema = 'secure'", "silently repoints unqualified names"),
    ("SET search_path = 'secure'", "silently repoints unqualified names"),
    ("USE secure", "silently repoints unqualified names"),
    # Statements dblocker cannot model must not be forwarded on trust.
    ("CALL pragma_table_info('events')", "invokes an unmodelled procedure"),
    ("PRAGMA database_list", "reads engine internals"),
    ("not valid sql (((", "unparseable, so its effect is unknown"),
    # EXPLAIN ANALYZE really executes its inner statement.
    ("EXPLAIN ANALYZE DELETE FROM analytics.events", "executes a delete under EXPLAIN"),
    # Ordinary out-of-scope access and mutation.
    ("SELECT * FROM secure.secrets", "reads outside the allowed schema"),
    ("SELECT * FROM evil.main.stolen", "reads outside the allowed catalog"),
    ("DROP TABLE analytics.events", "destroys data"),
    ("INSERT INTO analytics.events VALUES (1)", "mutates data"),
    ("SELECT * FROM analytics.events; DROP TABLE analytics.events;", "smuggles DDL in a batch"),
]

MUST_ALLOW = [
    ("SELECT * FROM analytics.events", "the legitimate read this proxy exists to serve"),
    ("SELECT count(*) FROM analytics.events WHERE id > 1", "an aggregate over an allowed table"),
    ("WITH c AS (SELECT 1 AS x) SELECT * FROM c", "a CTE that shadows no real table"),
    ("EXPLAIN SELECT * FROM analytics.events", "a read-only plan inspection"),
    ("BEGIN", "transaction control drivers issue automatically"),
    ("COMMIT", "transaction control drivers issue automatically"),
    ("SET extra_float_digits = 3", "a cosmetic setting drivers send when connecting"),
]
