"""Configuration model and YAML loader for dblocker."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

VALID_RULE_TYPES = {"schema_allowlist", "table_denylist", "statement_type_block", "regex"}
VALID_ACTIONS = {"allow", "deny"}


@dataclass
class ListenConfig:
    host: str = "0.0.0.0"
    port: int = 5432


@dataclass
class DownstreamConfig:
    host: str
    port: int
    user: str
    dbname: str
    password: str | None = None


@dataclass
class Rule:
    name: str
    type: str
    action: str = "deny"
    catalogs: list[str] = field(default_factory=list)
    schemas: list[str] = field(default_factory=list)
    tables: list[str] = field(default_factory=list)
    statement_types: list[str] = field(default_factory=list)
    pattern: str | None = None

    def __post_init__(self) -> None:
        if self.type not in VALID_RULE_TYPES:
            raise ValueError(f"rule {self.name!r}: unknown type {self.type!r}")
        if self.action not in VALID_ACTIONS:
            raise ValueError(f"rule {self.name!r}: action must be 'allow' or 'deny'")
        if self.type == "regex" and not self.pattern:
            raise ValueError(f"rule {self.name!r}: regex rule requires a 'pattern'")
        if self.type == "statement_type_block" and not self.statement_types:
            raise ValueError(f"rule {self.name!r}: requires 'statement_types'")
        if self.type == "table_denylist" and not self.tables:
            raise ValueError(f"rule {self.name!r}: requires 'tables'")
        if self.type == "schema_allowlist" and not self.schemas and not self.catalogs:
            raise ValueError(f"rule {self.name!r}: requires 'schemas' and/or 'catalogs'")

        # DuckDB folds unquoted identifiers to lowercase; normalize match
        # criteria once here so policy.py can compare case-insensitively.
        self.catalogs = [c.lower() for c in self.catalogs]
        self.schemas = [s.lower() for s in self.schemas]
        self.tables = [t.lower() for t in self.tables]
        self.statement_types = [s.lower() for s in self.statement_types]


@dataclass
class Config:
    listen: ListenConfig
    downstream: DownstreamConfig
    dialect: str = "duckdb"
    default_catalog: str = "memory"
    default_schema: str = "main"
    default_action: str = "allow"
    rules: list[Rule] = field(default_factory=list)


def load_config(path: str | Path) -> Config:
    data = yaml.safe_load(Path(path).read_text())
    listen = ListenConfig(**data.get("listen", {}))
    downstream = DownstreamConfig(**data["downstream"])
    rules = [Rule(**rule) for rule in data.get("rules", [])]
    return Config(
        listen=listen,
        downstream=downstream,
        dialect=data.get("dialect", "duckdb"),
        default_catalog=data.get("default_catalog", "memory"),
        default_schema=data.get("default_schema", "main"),
        default_action=data.get("default_action", "allow"),
        rules=rules,
    )
