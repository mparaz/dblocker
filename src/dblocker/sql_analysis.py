"""Wraps sqlglot to extract the facts policy rules need from a query."""

from __future__ import annotations

from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError


@dataclass(frozen=True)
class TableRef:
    catalog: str
    schema: str
    name: str

    @property
    def qualified_name(self) -> str:
        return f"{self.catalog}.{self.schema}.{self.name}"


@dataclass
class ParsedQuery:
    """The policy-relevant facts of a single SQL statement."""

    statement_type: str
    tables: list[TableRef] = field(default_factory=list)
    sets_catalog: str | None = None
    sets_schema: str | None = None
    parse_error: bool = False


def analyze(
    sql: str, *, dialect: str, default_catalog: str, default_schema: str
) -> list[ParsedQuery]:
    """Parse `sql` (which may contain multiple ;-separated statements) into
    one ParsedQuery per statement, so callers can enforce policy on every
    statement in a batch rather than only the first."""
    try:
        statements = sqlglot.parse(sql, dialect=dialect)
    except ParseError:
        return [ParsedQuery(statement_type="unknown", parse_error=True)]

    parsed = [
        _analyze_statement(statement, default_catalog.lower(), default_schema.lower())
        for statement in statements
        if statement is not None
    ]
    return parsed or [ParsedQuery(statement_type="unknown")]


def _analyze_statement(
    statement: exp.Expression, default_catalog: str, default_schema: str
) -> ParsedQuery:
    statement_type = statement.key

    if isinstance(statement, exp.Use):
        return _analyze_use(statement)

    # DuckDB folds unquoted identifiers to lowercase, so normalize here to
    # match case-insensitively downstream, same as everything else in this
    # module that touches a catalog/schema/table name.
    cte_names = {cte.alias_or_name.lower() for cte in statement.find_all(exp.CTE)}
    tables: list[TableRef] = []
    for table in statement.find_all(exp.Table):
        if not table.catalog and not table.db and table.name.lower() in cte_names:
            continue
        tables.append(
            TableRef(
                catalog=(table.catalog or default_catalog).lower(),
                schema=(table.db or default_schema).lower(),
                name=table.name.lower(),
            )
        )

    return ParsedQuery(statement_type=statement_type, tables=tables)


def _analyze_use(statement: exp.Use) -> ParsedQuery:
    statement_type = statement.key
    target = statement.this
    if not isinstance(target, exp.Table):
        return ParsedQuery(statement_type)

    if target.db:
        return ParsedQuery(
            statement_type, sets_catalog=target.db.lower(), sets_schema=target.name.lower()
        )

    kind = statement.args.get("kind")
    if kind is not None:
        # DuckDB has no notion of a USE "kind" (WAREHOUSE/ROLE/...); sqlglot's
        # generic USE grammar treats such reserved words as a `kind` keyword
        # rather than the first part of a catalog.schema path. Recover it.
        return ParsedQuery(
            statement_type, sets_catalog=kind.name.lower(), sets_schema=target.name.lower()
        )

    return ParsedQuery(statement_type, sets_schema=target.name.lower())
