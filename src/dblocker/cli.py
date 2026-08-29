"""Command-line entrypoint for dblocker."""

from __future__ import annotations

import logging
import sys

import click

from dblocker.core.config import ConfigError, load_config
from dblocker.pgwire.server import serve


@click.command()
@click.option(
    "--config",
    "config_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to a dblocker YAML config file.",
)
@click.option(
    "--log-level",
    default="INFO",
    show_default=True,
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
)
def main(config_path: str, log_level: str) -> None:
    """Start the dblocker Postgres-wire-protocol policy proxy."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        # A misread config is a security-relevant failure, so refuse to start
        # rather than falling back to some default posture.
        raise SystemExit(f"dblocker: invalid configuration: {exc}") from exc
    try:
        serve(config)
    except KeyboardInterrupt:
        print("dblocker: shutting down", file=sys.stderr)


if __name__ == "__main__":
    main()
