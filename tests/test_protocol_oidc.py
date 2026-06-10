from __future__ import annotations

import asyncio
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import respx
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey
from pydantic import AnyHttpUrl, SecretStr
from starlette.requests import Request

from authub.errors import InvalidStateError, ProtocolError
from authub.models import IdentityProvider, OidcSettings
from authub.protocols.base import HttpOptions
from authub.protocols.oidc import OidcProtocol

ISSUER = "https://idp.test"
IDP_KEY = RSAKey.generate_key(2048, auto_kid=True)


def make_conn(**settings_overrides: Any) -> IdentityProvider:
    return IdentityProvider(
        id="acme-oidc",
        tenant_id="acme",
        display_name="Test IdP",
        settings=OidcSettings(
            issuer=AnyHttpUrl(ISSUER),
            client_id="cid",
            client_secret=SecretStr("cs"),
            **settings_overrides,
        ),
    )


def mock_discovery(router: respx.MockRouter) -> None:
    router.get(f"{ISSUER}/.well-known/openid-configuration").respond(
        json={
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/jwks",
            "userinfo_endpoint": f"{ISSUER}/userinfo",
        }
    )
    router.get(f"{ISSUER}/jwks").respond(json=KeySet([IDP_KEY]).as_dict(private=False))


def make_id_token(nonce: str, **claims: Any) -> str:
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": "cid",
        "sub": "user-1",
        "email": "a@b.co",
        "iat": now,
        "exp": now + 300,
        "nonce": nonce,
        **claims,
    }
    return jwt.encode({"alg": "RS256", "kid": IDP_KEY.kid}, payload, IDP_KEY, algorithms=["RS256"])


def get_request(url: str) -> Request:
    parts = urlsplit(url)
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "http",
            "server": ("t", 80),
            "path": parts.path,
            "query_string": parts.query.encode(),
            "headers": [],
        }
    )


@respx.mock
async def test_begin_builds_authorize_url_and_state() -> None:
    mock_discovery(respx.mock)
    protocol = OidcProtocol()
    result = await protocol.begin(
        idp=make_conn(), callback_url="http://app/auth/acme-oidc/callback", return_to="/x"
    )
    parts = urlsplit(result.redirect_url)
    query = parse_qs(parts.query)
    assert result.redirect_url.startswith(f"{ISSUER}/authorize?")
    assert query["response_type"] == ["code"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"] == [result.flow_state.state]
    assert query["nonce"] == [result.flow_state.nonce]
    assert result.flow_state.code_verifier
    assert result.flow_state.return_to == "/x"


@respx.mock
async def test_complete_happy_path() -> None:
    mock_discovery(respx.mock)
    protocol = OidcProtocol()
    begin = await protocol.begin(idp=make_conn(), callback_url="http://app/cb", return_to="/")
    state = begin.flow_state
    assert state.nonce
    respx.mock.post(f"{ISSUER}/token").respond(
        json={
            "access_token": "at",
            "token_type": "Bearer",
            "id_token": make_id_token(nonce=state.nonce),
        }
    )
    request = get_request(f"http://app/cb?code=c1&state={state.state}")
    raw = await protocol.complete(
        request=request, idp=make_conn(), callback_url="http://app/cb", flow_state=state
    )
    assert raw.claims["sub"] == "user-1"
    assert raw.claims["email"] == "a@b.co"


@respx.mock
async def test_complete_rejects_state_mismatch() -> None:
    mock_discovery(respx.mock)
    protocol = OidcProtocol()
    begin = await protocol.begin(idp=make_conn(), callback_url="http://app/cb", return_to="/")
    request = get_request("http://app/cb?code=c1&state=WRONG")
    with pytest.raises(InvalidStateError):
        await protocol.complete(
            request=request,
            idp=make_conn(),
            callback_url="http://app/cb",
            flow_state=begin.flow_state,
        )


@respx.mock
async def test_complete_rejects_nonce_mismatch() -> None:
    mock_discovery(respx.mock)
    protocol = OidcProtocol()
    begin = await protocol.begin(idp=make_conn(), callback_url="http://app/cb", return_to="/")
    state = begin.flow_state
    respx.mock.post(f"{ISSUER}/token").respond(
        json={"access_token": "at", "id_token": make_id_token(nonce="EVIL")}
    )
    request = get_request(f"http://app/cb?code=c1&state={state.state}")
    with pytest.raises(ProtocolError):
        await protocol.complete(
            request=request, idp=make_conn(), callback_url="http://app/cb", flow_state=state
        )


@respx.mock
async def test_complete_rejects_expired_id_token() -> None:
    mock_discovery(respx.mock)
    protocol = OidcProtocol()
    begin = await protocol.begin(idp=make_conn(), callback_url="http://app/cb", return_to="/")
    state = begin.flow_state
    assert state.nonce
    expired = make_id_token(nonce=state.nonce, exp=int(time.time()) - 1000)
    respx.mock.post(f"{ISSUER}/token").respond(json={"access_token": "at", "id_token": expired})
    request = get_request(f"http://app/cb?code=c1&state={state.state}")
    with pytest.raises(ProtocolError):
        await protocol.complete(
            request=request, idp=make_conn(), callback_url="http://app/cb", flow_state=state
        )


@respx.mock
async def test_complete_rejects_wrong_audience() -> None:
    mock_discovery(respx.mock)
    protocol = OidcProtocol()
    begin = await protocol.begin(idp=make_conn(), callback_url="http://app/cb", return_to="/")
    state = begin.flow_state
    assert state.nonce
    respx.mock.post(f"{ISSUER}/token").respond(
        json={"access_token": "at", "id_token": make_id_token(nonce=state.nonce, aud="other")}
    )
    request = get_request(f"http://app/cb?code=c1&state={state.state}")
    with pytest.raises(ProtocolError):
        await protocol.complete(
            request=request, idp=make_conn(), callback_url="http://app/cb", flow_state=state
        )


@respx.mock
async def test_complete_surfaces_idp_error_param() -> None:
    mock_discovery(respx.mock)
    protocol = OidcProtocol()
    begin = await protocol.begin(idp=make_conn(), callback_url="http://app/cb", return_to="/")
    request = get_request("http://app/cb?error=access_denied")
    with pytest.raises(ProtocolError, match="access_denied"):
        await protocol.complete(
            request=request,
            idp=make_conn(),
            callback_url="http://app/cb",
            flow_state=begin.flow_state,
        )


@respx.mock
async def test_userinfo_cannot_override_id_token_claims() -> None:
    mock_discovery(respx.mock)
    protocol = OidcProtocol()
    begin = await protocol.begin(
        idp=make_conn(fetch_userinfo=True), callback_url="http://app/cb", return_to="/"
    )
    state = begin.flow_state
    assert state.nonce
    respx.mock.post(f"{ISSUER}/token").respond(
        json={
            "access_token": "at-1",
            "token_type": "Bearer",
            "id_token": make_id_token(nonce=state.nonce, email="real@b.co"),
        }
    )
    respx.mock.get(f"{ISSUER}/userinfo").respond(
        json={"sub": "user-1", "email": "attacker@evil.com", "extra": "bonus"}
    )
    request = get_request(f"http://app/cb?code=c1&state={state.state}")
    raw = await protocol.complete(
        request=request,
        idp=make_conn(fetch_userinfo=True),
        callback_url="http://app/cb",
        flow_state=state,
    )
    assert raw.claims["email"] == "real@b.co"
    assert raw.claims["extra"] == "bonus"


@respx.mock
async def test_discovery_issuer_mismatch_rejected() -> None:
    respx.mock.get(f"{ISSUER}/.well-known/openid-configuration").respond(
        json={"issuer": "https://evil.test", "authorization_endpoint": f"{ISSUER}/a"}
    )
    protocol = OidcProtocol()
    with pytest.raises(ProtocolError, match="issuer"):
        await protocol.begin(idp=make_conn(), callback_url="http://app/cb", return_to="/")


async def test_per_key_locks_allow_concurrent_discovery_of_different_issuers() -> None:
    """Per-issuer locking: a slow fetch for issuer A must not block issuer B."""
    issuer_a = "https://idp-a.test"
    issuer_b = "https://idp-b.test"

    gate = asyncio.Event()

    def _meta(issuer: str) -> dict[str, Any]:
        return {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "jwks_uri": f"{issuer}/jwks",
        }

    async def transport_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == f"{issuer_a}/.well-known/openid-configuration":
            await gate.wait()
            return httpx.Response(200, json=_meta(issuer_a))
        if url == f"{issuer_b}/.well-known/openid-configuration":
            return httpx.Response(200, json=_meta(issuer_b))
        if url == f"{issuer_a}/jwks" or url == f"{issuer_b}/jwks":
            return httpx.Response(
                200, json=KeySet([RSAKey.generate_key(2048, auto_kid=True)]).as_dict(private=False)
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler=transport_handler)
    http = HttpOptions()
    http.transport = transport
    http.timeout = 5.0
    protocol = OidcProtocol(http=http)

    idp_a = IdentityProvider(
        id="a",
        tenant_id="ta",
        display_name="A",
        settings=OidcSettings(
            issuer=AnyHttpUrl(issuer_a),
            client_id="c",
            client_secret=SecretStr("s"),
        ),
    )
    idp_b = IdentityProvider(
        id="b",
        tenant_id="tb",
        display_name="B",
        settings=OidcSettings(
            issuer=AnyHttpUrl(issuer_b),
            client_id="c",
            client_secret=SecretStr("s"),
        ),
    )

    task_a = asyncio.create_task(
        protocol.begin(idp=idp_a, callback_url="http://app/cb", return_to="/")
    )

    await asyncio.sleep(0)

    result_b = await asyncio.wait_for(
        protocol.begin(idp=idp_b, callback_url="http://app/cb", return_to="/"),
        timeout=2.0,
    )
    assert result_b.redirect_url.startswith(f"{issuer_b}/authorize")

    gate.set()
    result_a = await asyncio.wait_for(task_a, timeout=2.0)
    assert result_a.redirect_url.startswith(f"{issuer_a}/authorize")
