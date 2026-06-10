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
    Mapping,
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


# ---------------------------------------------------------------------------
# Claim mapping end-to-end
# ---------------------------------------------------------------------------


class FakeProtocolWithClaims(AuthProtocol):
    """Protocol that returns arbitrary claims supplied at construction time."""

    kind = "oidc"

    def __init__(self, claims: dict[str, Any]) -> None:
        self._claims = claims

    async def begin(self, *, conn: Any, callback_url: Any, return_to: Any) -> BeginResult:
        return BeginResult(
            redirect_url="https://idp/auth",
            flow_state=FlowState(connection_id=conn.id, return_to=return_to),
        )

    async def complete(
        self, *, request: Any, conn: Any, callback_url: Any, flow_state: Any
    ) -> RawIdentity:
        return RawIdentity(claims=self._claims)


def make_flow_with_mapping(
    raw_claims: dict[str, Any],
    mapping: Mapping,
    plugins: PluginChain | None = None,
) -> AuthFlow:
    conn = Connection(
        id="c1",
        tenant_id="acme",
        display_name="C",
        settings=OidcSettings(
            issuer=TypeAdapter(AnyHttpUrl).validate_python("https://i.test"),
            client_id="x",
            client_secret=SecretStr("y"),
        ),
        mapping=mapping,
    )
    registry = ProtocolRegistry()
    registry.register(FakeProtocolWithClaims(raw_claims))
    return AuthFlow(
        connections=InMemoryConnectionStore([conn]),
        users=InMemoryUserStore(),
        tokens=JwtTokenService.hs256("s" * 32),
        registry=registry,
        plugins=plugins or PluginChain(),
        mapper=Mapper(),
        user_token_ttl=timedelta(hours=1),
    )


async def test_claim_mapping_non_default_paths_and_lower_transform() -> None:
    """email from 'mail', roles from 'groups', 'lower' transform applied to email."""
    mapping = Mapping(
        external_id="sub",
        email="mail",
        roles="groups",
        transforms={"email": "lower"},
    )
    raw = {"sub": "u1", "mail": "Ada@TEST.COM", "groups": ["admin"]}
    flow = make_flow_with_mapping(raw, mapping)
    begin = await flow.begin(connection_id="c1", callback_url="http://a/cb", return_to="/")
    token, principal = await flow.complete(
        request=dummy_request(),
        connection_id="c1",
        callback_url="http://a/cb",
        flow_state=begin.flow_state,
    )
    # Email lowercased via transform
    assert principal.email == "ada@test.com"
    # Roles extracted from 'groups'
    assert principal.roles == ["admin"]
    # Token encodes the mapped identity
    claims = await flow.tokens.verify(token)
    assert claims.email == "ada@test.com"
    assert claims.roles == ["admin"]
    assert claims.tenant_id == "acme"


# ---------------------------------------------------------------------------
# Plugin hooks: on_identity and on_user_provisioned
# ---------------------------------------------------------------------------


async def test_on_identity_can_mutate_raw_claims() -> None:
    """on_identity hook can enrich RawIdentity claims before mapping."""

    class EnrichPlugin(Plugin):
        async def on_identity(self, raw: RawIdentity, conn: Connection) -> None:
            raw.claims["email"] = "enriched@example.com"

    raw = {"sub": "u1", "email": "original@example.com", "name": "Ada"}
    flow = make_flow_with_mapping(
        raw,
        Mapping(),
        plugins=PluginChain([EnrichPlugin()]),
    )
    begin = await flow.begin(connection_id="c1", callback_url="http://a/cb", return_to="/")
    _token, principal = await flow.complete(
        request=dummy_request(),
        connection_id="c1",
        callback_url="http://a/cb",
        flow_state=begin.flow_state,
    )
    assert principal.email == "enriched@example.com"


async def test_on_user_provisioned_is_called_with_principal() -> None:
    """on_user_provisioned is invoked exactly once with the provisioned principal."""
    provisioned: list[tuple[Principal, CanonicalIdentity]] = []

    class RecordPlugin(Plugin):
        async def on_user_provisioned(
            self, principal: Principal, identity: CanonicalIdentity
        ) -> None:
            provisioned.append((principal, identity))

    raw = {"sub": "u1", "email": "a@b.co", "name": "Ada"}
    flow = make_flow_with_mapping(
        raw,
        Mapping(),
        plugins=PluginChain([RecordPlugin()]),
    )
    begin = await flow.begin(connection_id="c1", callback_url="http://a/cb", return_to="/")
    _token, principal = await flow.complete(
        request=dummy_request(),
        connection_id="c1",
        callback_url="http://a/cb",
        flow_state=begin.flow_state,
    )
    assert len(provisioned) == 1
    recorded_principal, recorded_identity = provisioned[0]
    assert recorded_principal.id == principal.id
    assert recorded_identity.external_id == "u1"
