"""Wires the policy backend up to buenavista's Postgres wire protocol server."""

from __future__ import annotations

import logging

from buenavista.postgres import BuenaVistaServer

from dblocker.config import Config
from dblocker.proxy_backend import PolicyConnection

logger = logging.getLogger(__name__)


def build_connection(config: Config) -> PolicyConnection:
    downstream_kwargs = {
        "host": config.downstream.host,
        "port": config.downstream.port,
        "user": config.downstream.user,
        "dbname": config.downstream.dbname,
    }
    if config.downstream.password:
        downstream_kwargs["password"] = config.downstream.password

    return PolicyConnection(
        downstream_kwargs=downstream_kwargs,
        rules=config.rules,
        dialect=config.dialect,
        default_catalog=config.default_catalog,
        default_schema=config.default_schema,
        default_action=config.default_action,
    )


def serve(config: Config) -> None:
    connection = build_connection(config)
    address = (config.listen.host, config.listen.port)
    server = BuenaVistaServer(address, connection)
    logger.info(
        "dblocker listening on %s:%s -> downstream %s:%s (%d rules loaded)",
        config.listen.host,
        config.listen.port,
        config.downstream.host,
        config.downstream.port,
        len(config.rules),
    )
    server.serve_forever()
