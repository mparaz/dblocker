from __future__ import annotations

from pathlib import Path

import pytest

from dblocker.core.config import load_config

EXAMPLE_CONFIG = Path(__file__).resolve().parents[1] / "examples" / "dblocker.yaml"


@pytest.fixture
def example_config():
    """The shipped example policy.

    Tests run against the real example rather than a bespoke fixture so that
    the config users copy is itself covered by the bypass corpus.
    """
    return load_config(EXAMPLE_CONFIG)
