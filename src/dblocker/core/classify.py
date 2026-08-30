"""Classifies SQL into semantic statement classes and policy-relevant facts.

This module is the reason dblocker fails *closed*. The first version of
dblocker keyed policy off the tables a statement referenced, which meant any
statement that referenced no tables -- `ATTACH`, `INSTALL`, `COPY ... TO`,
`EXPORT DATABASE`, or anything sqlglot could not parse -- slipped past every
rule and hit the default action. Here every statement is instead assigned a
class up front, and anything unrecognised becomes `UNKNOWN`, which no allow
rule can ever match.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError


class StatementClass(StrEnum):
    READ = "read"
    WRITE = "write"
    DDL = "ddl"
    ADMIN = "admin"
    CONTEXT = "context"
    TRANSACTION = "transaction"
    UNKNOWN = "unknown"


# Mapped by expression type rather than sqlglot's `.key` strings, which are
# internal names that drift between sqlglot releases.
_READ_TYPES = (exp.Select, exp.Union, exp.Values, exp.Show, exp.Describe, exp.Summarize)
_WRITE_TYPES = (exp.Insert, exp.Update, exp.Delete, exp.Merge)
_DDL_TYPES = (exp.Create, exp.Drop, exp.Alter, exp.TruncateTable)
# COPY (either direction), ATTACH, DETACH, INSTALL and PRAGMA all reach data or
# settings outside the pinned context, so they are administrative regardless of
# which tables they happen to name.
_ADMIN_TYPES = (exp.Attach, exp.Detach, exp.Install, exp.Copy, exp.Pragma)
_CONTEXT_TYPES = (exp.Use, exp.Set)
_TRANSACTION_TYPES = (exp.Transaction, exp.Commit, exp.Rollback)

# Table functions that read from the filesystem, object storage or the network.
# Matched by exact name plus the `read_*` / `*_scan` conventions DuckDB uses.
_EXTERNAL_READ_FUNCTIONS = frozenset(
    {
        "glob",
        "parquet_scan",
        "iceberg_scan",
        "delta_scan",
        "st_read",
        "load_aws_credentials",
    }
)


def is_external_read_function(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered in _EXTERNAL_READ_FUNCTIONS
        or lowered.startswith("read_")
        or lowered.endswith("_scan")
    )


@dataclass(frozen=True)
class TableRef:
    catalog: str
    schema: str
    name: str

    @property
    def qualified_name(self) -> str:
        return f"{self.catalog}.{self.schema}.{self.name}"


@dataclass
class Analyzed:
    """The policy-relevant facts of a single SQL statement."""

    cls: StatementClass
    tables: list[TableRef] = field(default_factory=list)
    functions: set[str] = field(default_factory=set)
    reads_external_files: bool = False
    writes_external_files: bool = False
    sets_catalog: str | None = None
    sets_schema: str | None = None
    setting_names: list[str] = field(default_factory=list)


@dataclass
class AnalyzedBatch:
    statements: list[Analyzed]
    parse_error: bool = False

    @property
    def statement_count(self) -> int:
        return len(self.statements)


def analyze(sql: str, *, dialect: str, catalog: str, schema: str) -> AnalyzedBatch:
    """Parse `sql` into one `Analyzed` per statement.

    A parse failure is itself a policy-relevant fact: it yields a single
    `UNKNOWN` statement so the caller denies rather than forwarding SQL whose
    meaning dblocker could not establish.
    """
    try:
        parsed = sqlglot.parse(sql, dialect=dialect)
    except ParseError:
        return AnalyzedBatch(statements=[Analyzed(cls=StatementClass.UNKNOWN)], parse_error=True)

    statements = [
        _analyze_statement(statement, dialect, catalog.lower(), schema.lower())
        for statement in parsed
        if statement is not None
    ]
    if not statements:
        # Empty input or comments only; nothing to forward.
        return AnalyzedBatch(statements=[Analyzed(cls=StatementClass.UNKNOWN)])
    return AnalyzedBatch(statements=statements)


def _analyze_statement(
    statement: exp.Expression, dialect: str, catalog: str, schema: str
) -> Analyzed:
    if isinstance(statement, exp.Command):
        return _analyze_command(statement, dialect, catalog, schema)
    if isinstance(statement, exp.Use):
        return _analyze_use(statement, dialect)
    if isinstance(statement, exp.Set):
        return _analyze_set(statement)

    cls = _classify(statement)
    analyzed = Analyzed(cls=cls, tables=_extract_tables(statement, catalog, schema))
    _apply_function_facts(statement, analyzed)
    if isinstance(statement, exp.Copy):
        # COPY ... TO writes a file; COPY ... FROM reads one. Both are ADMIN, but
        # record the direction so rules and audit records can tell them apart.
        # sqlglot sets `kind` truthy for FROM and falsy for TO.
        if statement.args.get("kind"):
            analyzed.reads_external_files = True
        else:
            analyzed.writes_external_files = True
    return analyzed


def _classify(statement: exp.Expression) -> StatementClass:
    if isinstance(statement, _READ_TYPES):
        return StatementClass.READ
    if isinstance(statement, _WRITE_TYPES):
        return StatementClass.WRITE
    if isinstance(statement, _DDL_TYPES):
        return StatementClass.DDL
    if isinstance(statement, _ADMIN_TYPES):
        return StatementClass.ADMIN
    if isinstance(statement, _CONTEXT_TYPES):
        return StatementClass.CONTEXT
    if isinstance(statement, _TRANSACTION_TYPES):
        return StatementClass.TRANSACTION
    return StatementClass.UNKNOWN


def _analyze_command(statement: exp.Command, dialect: str, catalog: str, schema: str) -> Analyzed:
    """`Command` is sqlglot's fallback for syntax it cannot model.

    Everything here is UNKNOWN (and therefore denied) except EXPLAIN, whose
    class is taken from the statement it wraps. That keeps `EXPLAIN SELECT`
    usable as a read while `EXPLAIN ANALYZE DELETE` -- which really does
    execute the delete -- does not inherit read status.
    """
    if str(statement.this).upper() != "EXPLAIN":
        return Analyzed(cls=StatementClass.UNKNOWN)

    inner_sql = statement.args.get("expression")
    inner_text = inner_sql.this if isinstance(inner_sql, exp.Literal) else str(inner_sql or "")
    try:
        inner = sqlglot.parse_one(str(inner_text).strip(), dialect=dialect)
    except ParseError:
        return Analyzed(cls=StatementClass.UNKNOWN)
    if inner is None:
        return Analyzed(cls=StatementClass.UNKNOWN)
    return _analyze_statement(inner, dialect, catalog, schema)


def _analyze_use(statement: exp.Use, dialect: str) -> Analyzed:
    analyzed = Analyzed(cls=StatementClass.CONTEXT)
    target = statement.this
    if not isinstance(target, exp.Table):
        return analyzed

    if target.db:
        analyzed.sets_catalog = target.db.lower()
        analyzed.sets_schema = target.name.lower()
        return analyzed

    kind = statement.args.get("kind")
    if kind is not None and dialect == "duckdb":
        # DuckDB has no USE "kind" (WAREHOUSE/ROLE/...), but sqlglot's generic
        # USE grammar consumes such reserved words as `kind` rather than as the
        # catalog half of a catalog.schema path. Recover it for DuckDB only --
        # in Snowflake `USE ROLE x` genuinely means a role, not a catalog.
        analyzed.sets_catalog = kind.name.lower()
        analyzed.sets_schema = target.name.lower()
        return analyzed

    analyzed.sets_schema = target.name.lower()
    return analyzed


def _analyze_set(statement: exp.Set) -> Analyzed:
    analyzed = Analyzed(cls=StatementClass.CONTEXT)
    for item in statement.args.get("expressions") or []:
        name = _setting_name(item)
        if name is None:
            # A SET whose target cannot be read is not safely allowlistable.
            return Analyzed(cls=StatementClass.UNKNOWN)
        analyzed.setting_names.append(name)
        if name in ("schema", "search_path"):
            value = _setting_value(item)
            if value:
                analyzed.sets_schema = value.split(",")[0].strip().strip('"').lower()
    return analyzed


def _setting_name(item: exp.Expression) -> str | None:
    target = item.this if isinstance(item, exp.SetItem) else item
    if isinstance(target, exp.EQ):
        target = target.this
    if isinstance(target, exp.Column | exp.Identifier | exp.Var):
        return target.name.lower()
    return None


def _setting_value(item: exp.Expression) -> str | None:
    target = item.this if isinstance(item, exp.SetItem) else item
    if isinstance(target, exp.EQ):
        value = target.expression
        if isinstance(value, exp.Literal):
            return str(value.this)
        return value.name or None
    return None


def _extract_tables(statement: exp.Expression, catalog: str, schema: str) -> list[TableRef]:
    cte_names = {cte.alias_or_name.lower() for cte in statement.find_all(exp.CTE)}
    tables: list[TableRef] = []
    for table in statement.find_all(exp.Table):
        name = table.name.lower()
        if not name:
            # A FROM item with no name is a table function such as
            # read_csv_auto('/etc/passwd'); it is accounted for as an external
            # read rather than as a table reference.
            continue
        if not table.catalog and not table.db and name in cte_names:
            continue
        tables.append(
            TableRef(
                catalog=(table.catalog or catalog).lower(),
                schema=(table.db or schema).lower(),
                name=name,
            )
        )
    return tables


def _apply_function_facts(statement: exp.Expression, analyzed: Analyzed) -> None:
    for node in statement.find_all(exp.Func):
        name = node.sql_name() if isinstance(node, exp.Anonymous) else node.__class__.__name__
        if isinstance(node, exp.Anonymous):
            name = str(node.this)
        analyzed.functions.add(name.lower())
        if is_external_read_function(name):
            analyzed.reads_external_files = True

    # A FROM item that parsed to a Table with an empty name is a table function
    # whose callee sqlglot stored elsewhere; treat it as an external read so it
    # can never pass a `reads_external_files: false` rule.
    for table in statement.find_all(exp.Table):
        if not table.name:
            analyzed.reads_external_files = True
