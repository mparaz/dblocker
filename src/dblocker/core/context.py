"""The pinned execution context, and keeping the downstream session matched to it.

dblocker resolves unqualified table names against a catalog/schema it believes
the session is using. If that belief drifts from the downstream session's real
state, policy is evaluated against one context while the query executes in
another -- so a rule can pass while the query reads somewhere else entirely.

Two things cause drift: statements that change the context mid-session (refused
in `policy.evaluate` unless explicitly enabled), and pooled connections, which
`psycopg_pool` returns to the pool having only rolled back transactions -- it
does not reset `search_path`, temp tables or loaded extensions. So the context
is re-applied on every checkout rather than assumed.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from importlib.metadata import PackageNotFoundError, version

IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")


def _dblocker_version() -> str:
    try:
        return version("dblocker")
    except PackageNotFoundError:  # pragma: no cover - only when running uninstalled
        return "unknown"


def validate_identifier(value: str, what: str) -> str:
    if not IDENTIFIER.match(value):
        raise ValueError(
            f"{what} must be a plain SQL identifier (letters, digits, _ and $), got {value!r}"
        )
    return value


def quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


@dataclass(frozen=True)
class SessionContext:
    """Where a query will actually run, as dblocker understands it."""

    downstream_host: str
    downstream_port: int
    downstream_user: str
    downstream_dbname: str
    catalog: str
    schema: str
    dialect: str
    policy_sha256: str
    dblocker_version: str = ""

    def __post_init__(self) -> None:
        if not self.dblocker_version:
            object.__setattr__(self, "dblocker_version", _dblocker_version())
        validate_identifier(self.catalog, "context.catalog")
        validate_identifier(self.schema, "context.schema")

    def context_hash(self) -> str:
        """A stable digest of everything that determines where a query lands.

        Two sessions sharing this hash ran against the same endpoint, database,
        catalog, schema and policy.
        """
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode("utf-8")).hexdigest()

    def reset_statements(self) -> list[str]:
        """SQL that forces a downstream session back to this context.

        Issued by dblocker itself on connection checkout, so it deliberately
        bypasses policy and is never attributed to the caller.
        """
        schema = quote_identifier(self.schema)
        if self.dialect == "duckdb":
            return [f"USE {quote_identifier(self.catalog)}.{schema}"]
        return ["RESET ALL", f"SET search_path TO {schema}"]

    def describe(self) -> dict[str, str]:
        return {
            "context_hash": self.context_hash(),
            "downstream": f"{self.downstream_host}:{self.downstream_port}/{self.downstream_dbname}",
            "catalog": self.catalog,
            "schema": self.schema,
            "dialect": self.dialect,
            "policy_sha256": self.policy_sha256,
            "dblocker_version": self.dblocker_version,
        }
