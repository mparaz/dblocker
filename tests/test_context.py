from __future__ import annotations

import pytest

from dblocker.core.config import (
    AuthConfig,
    AuthUser,
    Config,
    ConfigError,
    ContextConfig,
    DownstreamConfig,
    ListenConfig,
)
from dblocker.core.context import SessionContext, quote_identifier, validate_identifier


def make_context(**overrides) -> SessionContext:
    params = {
        "downstream_host": "localhost",
        "downstream_port": 5433,
        "downstream_user": "u",
        "downstream_dbname": "memory",
        "catalog": "memory",
        "schema": "analytics",
        "dialect": "duckdb",
        "policy_sha256": "abc",
    }
    params.update(overrides)
    return SessionContext(**params)


def test_context_hash_is_stable_for_the_same_context():
    assert make_context().context_hash() == make_context().context_hash()


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "other"),
        ("catalog", "other"),
        ("downstream_port", 9999),
        ("downstream_dbname", "other"),
        ("policy_sha256", "different"),
    ],
)
def test_context_hash_changes_when_where_it_runs_changes(field, value):
    """The hash must move whenever the effective destination or governing
    policy moves, so it can identify what a query actually ran against."""
    assert make_context().context_hash() != make_context(**{field: value}).context_hash()


def test_duckdb_reset_pins_catalog_and_schema():
    statements = make_context(dialect="duckdb").reset_statements()
    assert statements == ['USE "memory"."analytics"']


def test_postgres_reset_clears_then_pins():
    statements = make_context(dialect="postgres").reset_statements()
    assert statements == ["RESET ALL", 'SET search_path TO "analytics"']


def test_identifiers_are_validated_at_construction():
    with pytest.raises(ValueError, match="context.schema"):
        make_context(schema="public; DROP TABLE x")


@pytest.mark.parametrize("value", ["a b", "a-b", "a;b", "a'b", '"a"', "", "1a"])
def test_invalid_identifiers_are_rejected(value):
    with pytest.raises(ValueError):
        validate_identifier(value, "test")


def test_embedded_quotes_are_escaped():
    assert quote_identifier('we"ird') == '"we""ird"'


def test_describe_exposes_no_credentials():
    described = make_context().describe()
    assert "password" not in " ".join(described).lower()
    assert described["context_hash"] == make_context().context_hash()


def _config(listen: ListenConfig, auth: AuthConfig) -> Config:
    return Config(
        listen=listen,
        downstream=DownstreamConfig(host="h", port=1, user="u", dbname="d"),
        auth=auth,
        context=ContextConfig(),
    )


def test_non_loopback_bind_without_auth_is_refused():
    with pytest.raises(ConfigError, match="not loopback"):
        _config(ListenConfig(host="0.0.0.0", port=6432), AuthConfig(required=False))


def test_non_loopback_bind_with_auth_is_accepted():
    config = _config(
        ListenConfig(host="0.0.0.0", port=6432),
        AuthConfig(required=True, users=[AuthUser(name="agent", password_env="X")]),
    )
    assert not config.listen.is_loopback


def test_auth_required_without_users_is_refused():
    with pytest.raises(ConfigError, match="no auth.users"):
        _config(ListenConfig(), AuthConfig(required=True))


def test_loopback_without_auth_is_allowed():
    assert _config(ListenConfig(host="127.0.0.1", port=6432), AuthConfig(required=False))


def test_missing_password_env_is_reported_clearly(monkeypatch):
    monkeypatch.delenv("DBLOCKER_TEST_SECRET", raising=False)
    downstream = DownstreamConfig(
        host="h", port=1, user="u", dbname="d", password_env="DBLOCKER_TEST_SECRET"
    )
    with pytest.raises(ConfigError, match="not set in the environment"):
        downstream.password()


def test_password_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("DBLOCKER_TEST_SECRET", "s3cret")
    downstream = DownstreamConfig(
        host="h", port=1, user="u", dbname="d", password_env="DBLOCKER_TEST_SECRET"
    )
    assert downstream.password() == "s3cret"
