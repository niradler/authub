from __future__ import annotations

from authub import __version__, get_version


def test_version_matches() -> None:
    assert get_version() == __version__ == "0.1.0"
