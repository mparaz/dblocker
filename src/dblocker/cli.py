"""Command-line entrypoint for dblocker."""

from __future__ import annotations

import logging

import click

from dblocker.config import load_config
from dblocker.server import serve


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
    config = load_config(config_path)
    serve(config)


if __name__ == "__main__":
    main()
