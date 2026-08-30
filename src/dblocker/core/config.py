"""Configuration model and YAML loader for dblocker."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from dblocker.core.classify import StatementClass
from dblocker.core.evidence import EvidenceConfig

VALID_ACTIONS = {"allow", "deny"}
VALID_WRITE_FAILURE_MODES = {"deny", "continue"}

# Session settings a Postgres client may set during its own handshake. These
# are cosmetic or protocol-level and do not change which data is reachable, so
# they stay allowed even under a deny-by-default posture -- without them,
# ordinary drivers cannot complete a connection.
DEFAULT_SESSION_SETTINGS_ALLOWLIST = [
    "application_name",
    "client_encoding",
    "client_min_messages",
    "datestyle",
    "extra_float_digits",
    "intervalstyle",
    "standard_conforming_strings",
    "timezone",
]


class ConfigError(ValueError):
    """Raised when a config file is structurally or semantically invalid."""


@dataclass
class ListenConfig:
    host: str = "127.0.0.1"
    port: int = 6432

    @property
    def is_loopback(self) -> bool:
        return self.host in ("127.0.0.1", "::1", "localhost")


@dataclass
class DownstreamConfig:
    host: str
    port: int
    user: str
    dbname: str
    password_env: str | None = None

    def password(self) -> str | None:
        if self.password_env is None:
            return None
        secret = os.environ.get(self.password_env)
        if secret is None:
            raise ConfigError(
                f"downstream.password_env names {self.password_env!r}, "
                "which is not set in the environment"
            )
        return secret


@dataclass
class AuthUser:
    name: str
    password_env: str

    def password(self) -> str:
        secret = os.environ.get(self.password_env)
        if secret is None:
            raise ConfigError(
                f"auth user {self.name!r} names password_env {self.password_env!r}, "
                "which is not set in the environment"
            )
        return secret


@dataclass
class AuthConfig:
    # Defaults to off so a minimal config works for local use. The safety net
    # is not this flag but `Config.__post_init__`, which refuses to bind a
    # non-loopback address without authentication -- one invariant, enforced
    # however the Config was built.
    required: bool = False
    users: list[AuthUser] = field(default_factory=list)

    def credentials(self) -> dict[str, str]:
        return {user.name: user.password() for user in self.users}


@dataclass
class ContextConfig:
    catalog: str = "memory"
    schema: str = "main"
    allow_context_switch: bool = False
    session_settings_allowlist: list[str] = field(
        default_factory=lambda: list(DEFAULT_SESSION_SETTINGS_ALLOWLIST)
    )

    def __post_init__(self) -> None:
        self.catalog = self.catalog.lower()
        self.schema = self.schema.lower()
        self.session_settings_allowlist = [s.lower() for s in self.session_settings_allowlist]


@dataclass
class LimitsConfig:
    max_rows: int = 10_000
    max_bytes: int = 32 * 1024 * 1024
    statement_timeout_ms: int = 30_000
    single_statement_only: bool = True
    fetch_batch_size: int = 1_000


@dataclass
class Match:
    """Predicates for a rule. Every predicate that is set must hold."""

    statement_class: list[str] | None = None
    all_tables_in: dict[str, list[str]] | None = None
    tables_match: list[str] | None = None
    tables_not_match: list[str] | None = None
    reads_external_files: bool | None = None
    writes_external_files: bool | None = None
    regex: str | None = None
    not_regex: str | None = None
    capability: list[str] | None = None

    def __post_init__(self) -> None:
        if self.statement_class is not None:
            valid = {c.value for c in StatementClass}
            self.statement_class = [c.lower() for c in self.statement_class]
            unknown = set(self.statement_class) - valid
            if unknown:
                raise ConfigError(
                    f"unknown statement_class {sorted(unknown)}; valid values are {sorted(valid)}"
                )
        if self.all_tables_in is not None:
            self.all_tables_in = {
                key: [v.lower() for v in values] for key, values in self.all_tables_in.items()
            }
            unknown_keys = set(self.all_tables_in) - {"catalogs", "schemas"}
            if unknown_keys:
                raise ConfigError(
                    f"all_tables_in accepts 'catalogs' and 'schemas', got {sorted(unknown_keys)}"
                )
        for attr in ("tables_match", "tables_not_match"):
            value = getattr(self, attr)
            if value is not None:
                setattr(self, attr, [v.lower() for v in value])
        if self.capability is not None:
            self.capability = [c.lower() for c in self.capability]

    @property
    def is_empty(self) -> bool:
        return all(getattr(self, f) is None for f in self.__dataclass_fields__)


@dataclass
class Rule:
    name: str
    action: str
    match: Match

    def __post_init__(self) -> None:
        if self.action not in VALID_ACTIONS:
            raise ConfigError(f"rule {self.name!r}: action must be 'allow' or 'deny'")
        if self.action == "allow" and self.match.is_empty:
            raise ConfigError(
                f"rule {self.name!r}: an allow rule with no predicates would permit everything"
            )


@dataclass
class Config:
    listen: ListenConfig
    downstream: DownstreamConfig
    auth: AuthConfig = field(default_factory=AuthConfig)
    context: ContextConfig = field(default_factory=ContextConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    evidence: EvidenceConfig = field(default_factory=EvidenceConfig)
    dialect: str = "duckdb"
    default_action: str = "deny"
    allow_permissive_default: bool = False
    capabilities_enabled: list[str] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)
    policy_sha256: str = ""

    def __post_init__(self) -> None:
        if self.evidence.on_write_failure not in VALID_WRITE_FAILURE_MODES:
            raise ConfigError(
                "evidence.on_write_failure must be 'deny' or 'continue', "
                f"got {self.evidence.on_write_failure!r}"
            )
        if self.default_action not in VALID_ACTIONS:
            raise ConfigError(
                f"default_action must be 'allow' or 'deny', got {self.default_action!r}"
            )
        if self.default_action == "allow" and not self.allow_permissive_default:
            raise ConfigError(
                "default_action: allow disables dblocker's fail-closed posture. "
                "Set allow_permissive_default: true to confirm this is deliberate."
            )
        if self.auth.required and not self.auth.users:
            raise ConfigError("auth.required is true but no auth.users are configured")
        if not self.auth.required and not self.listen.is_loopback:
            raise ConfigError(
                f"auth.required is false but dblocker would listen on {self.listen.host}, "
                "which is not loopback; unauthenticated non-local access is refused"
            )


def _build_match(raw: Any, rule_name: str) -> Match:
    if raw is None:
        return Match()
    if not isinstance(raw, dict):
        raise ConfigError(f"rule {rule_name!r}: 'match' must be a mapping")
    known = set(Match.__dataclass_fields__)
    unknown = set(raw) - known
    if unknown:
        raise ConfigError(
            f"rule {rule_name!r}: unknown match predicate(s) {sorted(unknown)}; "
            f"valid predicates are {sorted(known)}"
        )
    return Match(**raw)


def _build_rule(raw: Any) -> Rule:
    if not isinstance(raw, dict):
        raise ConfigError("each entry of 'rules' must be a mapping")
    name = raw.get("name")
    if not name:
        raise ConfigError("every rule needs a 'name'")
    unknown = set(raw) - {"name", "action", "match"}
    if unknown:
        raise ConfigError(f"rule {name!r}: unknown key(s) {sorted(unknown)}")
    return Rule(
        name=name,
        action=raw.get("action", "deny"),
        match=_build_match(raw.get("match"), name),
    )


def _build_auth(raw: Any) -> AuthConfig:
    if raw is None:
        return AuthConfig(required=False)
    users = [AuthUser(**user) for user in raw.get("users", [])]
    return AuthConfig(required=raw.get("required", True), users=users)


def _build_evidence(raw: Any, config_path: Path) -> EvidenceConfig:
    raw = raw or {}
    known = set(EvidenceConfig.__dataclass_fields__)
    unknown = set(raw) - known
    if unknown:
        raise ConfigError(
            f"unknown evidence setting(s) {sorted(unknown)}; valid settings are {sorted(known)}"
        )
    values = dict(raw)
    # Relative store paths resolve against the config file, not the working
    # directory, so where dblocker is launched from cannot silently move the
    # ledger somewhere new.
    for key in ("ledger_path", "sql_store_path"):
        if key in values:
            path = Path(values[key])
            values[key] = path if path.is_absolute() else config_path.parent / path
    return EvidenceConfig(**values)


def load_config(path: str | Path) -> Config:
    config_path = Path(path).resolve()
    text = config_path.read_text()
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ConfigError("config file must contain a YAML mapping at the top level")
    if "downstream" not in data:
        raise ConfigError("config file must define a 'downstream' section")

    config = Config(
        listen=ListenConfig(**data.get("listen", {})),
        downstream=DownstreamConfig(**data["downstream"]),
        auth=_build_auth(data.get("auth")),
        context=ContextConfig(**data.get("context", {})),
        limits=LimitsConfig(**data.get("limits", {})),
        evidence=_build_evidence(data.get("evidence"), config_path),
        dialect=data.get("dialect", "duckdb"),
        default_action=data.get("default_action", "deny"),
        allow_permissive_default=data.get("allow_permissive_default", False),
        capabilities_enabled=data.get("capabilities", {}).get("enabled", []),
        rules=[_build_rule(rule) for rule in data.get("rules", [])],
    )
    # Identifies the exact policy a decision was made under. The deferred
    # evidence ledger records this alongside every decision.
    config.policy_sha256 = hashlib.sha256(
        json.dumps(
            {"rules": data.get("rules", []), "default_action": config.default_action},
            sort_keys=True,
            default=str,
        ).encode()
    ).hexdigest()
    return config
