"""Named canonical queries, so an agent can investigate without writing SQL.

A capability is invoked in-band and never reaches the downstream as written:

    SELECT * FROM dblocker.capability('describe_table', 'analytics.events')

dblocker renders the statement itself from a template and validated arguments,
then puts the rendered SQL through the *same* policy and bounds path as any
other query. Naming a capability therefore grants no extra reach: asking for
`row_sample` of a table outside the allowed scope renders a read of that table,
which the ordinary rules then refuse.

Arguments are never handed to a SQL parser. Identifier arguments are validated
character by character and rebuilt as AST identifiers; value arguments become
string literals, which sqlglot escapes on generation.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError

from dblocker.core.context import SessionContext, validate_identifier

MAX_SAMPLE_ROWS = 1_000


class CapabilityError(ValueError):
    """Raised when a capability call is unknown, disabled or malformed."""


@dataclass(frozen=True)
class CapabilityCall:
    name: str
    args: tuple[str, ...]


def parse_capability_call(sql: str, *, dialect: str) -> CapabilityCall | None:
    """Recognise `SELECT ... FROM dblocker.capability('name', ...)`.

    Returns None for anything that is not such a call, so ordinary SQL falls
    through untouched.
    """
    try:
        tree = sqlglot.parse_one(sql, dialect=dialect)
    except ParseError:
        return None
    if not isinstance(tree, exp.Select):
        return None
    # Located via find() rather than args["from"]: sqlglot has renamed that key
    # between releases (it is "from_" as of 30.x).
    source = tree.find(exp.From)
    if source is None:
        return None
    table = source.this
    if not isinstance(table, exp.Table):
        return None
    if (table.db or "").lower() != "dblocker":
        return None
    func = table.this
    if not isinstance(func, exp.Anonymous) or str(func.this).lower() != "capability":
        return None

    args: list[str] = []
    for argument in func.expressions:
        if not isinstance(argument, exp.Literal):
            raise CapabilityError("capability arguments must be literals")
        args.append(str(argument.this))
    if not args:
        raise CapabilityError("dblocker.capability() needs a capability name")
    return CapabilityCall(name=args[0].lower(), args=tuple(args[1:]))


def _qualified(target: str, context: SessionContext) -> exp.Table:
    """Turn `a`, `a.b` or `a.b.c` into a Table, validating every part."""
    parts = target.split(".")
    if not 1 <= len(parts) <= 3:
        raise CapabilityError(
            f"target {target!r} must be table, schema.table or catalog.schema.table"
        )
    for part in parts:
        validate_identifier(part, "capability target")
    if len(parts) == 1:
        catalog, schema, name = context.catalog, context.schema, parts[0]
    elif len(parts) == 2:
        catalog, schema, name = context.catalog, parts[0], parts[1]
    else:
        catalog, schema, name = parts
    return exp.table_(name, db=schema, catalog=catalog)


def _metadata_table(name: str, context: SessionContext) -> exp.Table:
    # Deliberately not catalog-qualified: DuckDB rejects
    # `<catalog>.information_schema.x` outright, and the unqualified form is
    # what both DuckDB and Postgres accept. The classifier still resolves it to
    # the pinned catalog, so policy sees a normal table reference.
    return exp.table_(name, db="information_schema")


def _require_args(call: CapabilityCall, minimum: int, maximum: int) -> None:
    if not minimum <= len(call.args) <= maximum:
        raise CapabilityError(
            f"capability {call.name!r} takes between {minimum} and {maximum} "
            f"argument(s), got {len(call.args)}"
        )


def _list_schemas(call: CapabilityCall, context: SessionContext) -> exp.Expression:
    _require_args(call, 0, 0)
    return (
        exp.select("schema_name")
        .from_(_metadata_table("schemata", context))
        .order_by("schema_name")
    )


def _list_tables(call: CapabilityCall, context: SessionContext) -> exp.Expression:
    _require_args(call, 0, 1)
    schema = call.args[0] if call.args else context.schema
    validate_identifier(schema, "capability target")
    return (
        exp.select("table_schema", "table_name", "table_type")
        .from_(_metadata_table("tables", context))
        .where(exp.column("table_schema").eq(exp.Literal.string(schema)))
        .order_by("table_name")
    )


def _describe_table(call: CapabilityCall, context: SessionContext) -> exp.Expression:
    _require_args(call, 1, 1)
    table = _qualified(call.args[0], context)
    return (
        exp.select("column_name", "data_type", "is_nullable", "ordinal_position")
        .from_(_metadata_table("columns", context))
        .where(exp.column("table_schema").eq(exp.Literal.string(table.db)))
        .where(exp.column("table_name").eq(exp.Literal.string(table.name)))
        .order_by("ordinal_position")
    )


def _table_row_count(call: CapabilityCall, context: SessionContext) -> exp.Expression:
    _require_args(call, 1, 1)
    return exp.select(exp.func("count", exp.Star()).as_("row_count")).from_(
        _qualified(call.args[0], context)
    )


def _column_stats(call: CapabilityCall, context: SessionContext) -> exp.Expression:
    _require_args(call, 2, 2)
    table = _qualified(call.args[0], context)
    column_name = validate_identifier(call.args[1], "capability column")
    column = exp.column(column_name)
    return exp.select(
        exp.func("count", exp.Star()).as_("row_count"),
        exp.func("count", column.copy()).as_("non_null_count"),
        exp.func("count", exp.Distinct(expressions=[column.copy()])).as_("distinct_count"),
        exp.func("min", column.copy()).as_("min_value"),
        exp.func("max", column.copy()).as_("max_value"),
    ).from_(table)


def _row_sample(call: CapabilityCall, context: SessionContext) -> exp.Expression:
    _require_args(call, 1, 2)
    table = _qualified(call.args[0], context)
    limit = 10
    if len(call.args) == 2:
        try:
            limit = int(call.args[1])
        except (TypeError, ValueError) as exc:
            raise CapabilityError("row_sample's second argument must be an integer") from exc
        if not 1 <= limit <= MAX_SAMPLE_ROWS:
            raise CapabilityError(f"row_sample size must be between 1 and {MAX_SAMPLE_ROWS}")
    return exp.select(exp.Star()).from_(table).limit(limit)


Renderer = Callable[[CapabilityCall, SessionContext], exp.Expression]

REGISTRY: dict[str, tuple[str, Renderer]] = {
    "list_schemas": ("List schemas visible in the pinned catalog.", _list_schemas),
    "list_tables": ("List tables in a schema (defaults to the pinned schema).", _list_tables),
    "describe_table": ("Column names, types and nullability for a table.", _describe_table),
    "table_row_count": ("Count rows in a table.", _table_row_count),
    "column_stats": ("Row/non-null/distinct counts and min/max for one column.", _column_stats),
    "row_sample": ("Return a bounded sample of rows from a table.", _row_sample),
}


def render(call: CapabilityCall, *, context: SessionContext, enabled: list[str]) -> str:
    """Render a capability call to canonical SQL."""
    entry = REGISTRY.get(call.name)
    if entry is None:
        raise CapabilityError(f"unknown capability {call.name!r}; available: {sorted(REGISTRY)}")
    if call.name not in enabled:
        raise CapabilityError(f"capability {call.name!r} is not enabled in this configuration")
    _, renderer = entry
    return renderer(call, context).sql(dialect=context.dialect)
