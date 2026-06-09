from __future__ import annotations

import pytest

from authub.errors import UnknownProtocolError
from authub.protocols.base import AuthProtocol, HttpOptions, ProtocolRegistry


def test_registry_get_unknown_raises() -> None:
    registry = ProtocolRegistry()
    with pytest.raises(UnknownProtocolError):
        registry.get("nope")


def test_registry_register_and_get() -> None:
    from starlette.requests import Request

    from authub.models import Connection, RawIdentity
    from authub.state import BeginResult, FlowState

    class Fake(AuthProtocol):
        kind = "fake"

        async def begin(
            self, *, conn: Connection, callback_url: str, return_to: str
        ) -> BeginResult:
            raise NotImplementedError

        async def complete(
            self,
            *,
            request: Request,
            conn: Connection,
            callback_url: str,
            flow_state: FlowState,
        ) -> RawIdentity:
            raise NotImplementedError

    registry = ProtocolRegistry()
    registry.register(Fake())
    assert registry.get("fake").kind == "fake"


def test_http_options_builds_client() -> None:
    options = HttpOptions()
    client = options.client()
    assert client.timeout.connect == 10.0
