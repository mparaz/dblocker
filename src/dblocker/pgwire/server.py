"""Wires the policy backend to the Postgres wire protocol listener."""

from __future__ import annotations

import logging

from dblocker.core.config import Config
from dblocker.core.evidence import EvidenceLog
from dblocker.pgwire.backend import PolicyConnection
from dblocker.pgwire.errors import DblockerServer

logger = logging.getLogger(__name__)


def build_server(config: Config, evidence: EvidenceLog) -> tuple[DblockerServer, PolicyConnection]:
    """Returns the server and its connection; the connection is handed back so
    callers keep a typed handle on the pinned context."""
    connection = PolicyConnection(config, evidence)
    auth = config.auth.credentials() if config.auth.required else None
    server = DblockerServer(
        (config.listen.host, config.listen.port),
        connection,
        auth=auth,
    )
    return server, connection


def serve(config: Config, evidence: EvidenceLog) -> None:
    server, connection = build_server(config, evidence)
    context = connection.context
    logger.info(
        "dblocker listening on %s:%s -> %s:%s | context=%s.%s hash=%s | "
        "default_action=%s rules=%d auth=%s | ledger=%s",
        config.listen.host,
        config.listen.port,
        config.downstream.host,
        config.downstream.port,
        context.catalog,
        context.schema,
        context.context_hash()[:12],
        config.default_action,
        len(config.rules),
        "required" if config.auth.required else "disabled (loopback only)",
        config.evidence.ledger_path if config.evidence.enabled else "disabled",
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
