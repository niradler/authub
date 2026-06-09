from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from pydantic import AnyHttpUrl, SecretStr, TypeAdapter
from starlette.requests import Request

from authub.errors import ConnectionNotFoundError, ForbiddenError
from authub.flow import AuthFlow
from authub.mapping import Mapper
from authub.models import (
    CanonicalIdentity,
    Connection,
    OidcSettings,
    Principal,
    RawIdentity,
)
from authub.plugins import Plugin, PluginChain
from authub.protocols.base import AuthProtocol, ProtocolRegistry
from authub.state import BeginResult, FlowState
from authub.stores.memory import InMemoryConnectionStore, InMemoryUserStore
from authub.tokens.jwt import JwtTokenService


class FakeProtocol(AuthProtocol):
    kind = "oidc"

    async def begin(self, *, conn: Any, callback_url: Any, return_to: Any) -> BeginResult:
        return BeginResult(
            redirect_url="https://idp/auth",
            flow_state=FlowState(connection_id=conn.id, return_to=return_to),
        )

    async def complete(
        self, *, request: Any, conn: Any, callback_url: Any, flow_state: Any
    ) -> RawIdentity:
        return RawIdentity(claims={"sub": "ext-1", "email": "a@b.co", "name": "Ada"})


def dummy_request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "http",
            "server": ("t", 80),
            "path": "/",
            "query_string": b"",
            "headers": [],
        }
    )


def make_flow(plugins: PluginChain | None = None) -> AuthFlow:
    conn = Connection(
        id="c1",
        tenant_id="acme",
        display_name="C",
        settings=OidcSettings(
            issuer=TypeAdapter(AnyHttpUrl).validate_python("https://i.test"),
            client_id="x",
            client_secret=SecretStr("y"),
        ),
    )
    registry = ProtocolRegistry()
    registry.register(FakeProtocol())
    return AuthFlow(
        connections=InMemoryConnectionStore([conn]),
        users=InMemoryUserStore(),
        tokens=JwtTokenService.hs256("s" * 32),
        registry=registry,
        plugins=plugins or PluginChain(),
        mapper=Mapper(),
        user_token_ttl=timedelta(hours=1),
    )


async def test_begin_unknown_connection() -> None:
    flow = make_flow()
    with pytest.raises(ConnectionNotFoundError):
        await flow.begin(connection_id="nope", callback_url="http://a/cb", return_to="/")


async def test_complete_provisions_and_issues_token() -> None:
    flow = make_flow()
    begin = await flow.begin(connection_id="c1", callback_url="http://a/cb", return_to="/x")
    token, principal = await flow.complete(
        request=dummy_request(),
        connection_id="c1",
        callback_url="http://a/cb",
        flow_state=begin.flow_state,
    )
    assert principal.email == "a@b.co"
    claims = await flow.tokens.verify(token)
    assert claims.sub == principal.id
    assert claims.tenant_id == "acme"


async def test_plugin_can_stamp_and_reject() -> None:
    class Stamp(Plugin):
        async def before_issue_token(
            self,
            claims: dict[str, Any],
            principal: Principal,
            identity: CanonicalIdentity | None,
        ) -> dict[str, Any]:
            return {**claims, "plan": "pro"}

    flow = make_flow(PluginChain([Stamp()]))
    begin = await flow.begin(connection_id="c1", callback_url="http://a/cb", return_to="/")
    token, _ = await flow.complete(
        request=dummy_request(),
        connection_id="c1",
        callback_url="http://a/cb",
        flow_state=begin.flow_state,
    )
    claims = await flow.tokens.verify(token)
    assert claims.claims["plan"] == "pro"

    class Deny(Plugin):
        async def before_issue_token(
            self, claims: dict[str, Any], principal: Principal, identity: CanonicalIdentity | None
        ) -> dict[str, Any]:
            raise ForbiddenError("seats exceeded")

    flow = make_flow(PluginChain([Deny()]))
    begin = await flow.begin(connection_id="c1", callback_url="http://a/cb", return_to="/")
    with pytest.raises(ForbiddenError):
        await flow.complete(
            request=dummy_request(),
            connection_id="c1",
            callback_url="http://a/cb",
            flow_state=begin.flow_state,
        )
