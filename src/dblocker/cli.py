"""Command-line entrypoints for dblocker."""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from typing import Any

import click

from dblocker.core.config import Config, ConfigError, load_config
from dblocker.core.evidence import EvidenceLog

config_option = click.option(
    "--config",
    "config_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to a dblocker YAML config file.",
)
log_level_option = click.option(
    "--log-level",
    default="INFO",
    show_default=True,
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
)


def _start(
    config_path: str, log_level: str, stream: Any, run: Callable[[Config, EvidenceLog], None]
) -> None:
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=stream,
    )
    try:
        config = load_config(config_path)
        evidence = EvidenceLog(config.evidence)
        # Verified before serving: if provenance cannot be written, dblocker
        # would have to refuse every query anyway, so failing here says why.
        evidence.prepare()
    except (ConfigError, OSError) as exc:
        raise SystemExit(f"dblocker: cannot start: {exc}") from exc
    try:
        run(config, evidence)
    except KeyboardInterrupt:
        print("dblocker: shutting down", file=sys.stderr)


@click.group()
def main() -> None:
    """A SQL policy proxy that records what it let through."""


@main.command()
@config_option
@log_level_option
def serve(config_path: str, log_level: str) -> None:
    """Serve the Postgres wire protocol for psql, dbt and BI clients."""
    from dblocker.pgwire.server import serve as serve_pgwire

    _start(config_path, log_level, sys.stderr, serve_pgwire)


@main.command()
@config_option
@log_level_option
def mcp(config_path: str, log_level: str) -> None:
    """Serve MCP over stdio, returning provenance alongside every result."""
    from dblocker.mcp.server import serve as serve_mcp

    # stdout is the MCP transport; a stray log line there corrupts the stream.
    _start(config_path, log_level, sys.stderr, serve_mcp)


if __name__ == "__main__":
    main()
