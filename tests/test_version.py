from __future__ import annotations

from importlib import metadata

import authub


def test_version_matches() -> None:
    assert authub.__version__ == metadata.version("authub")
