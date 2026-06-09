from __future__ import annotations

import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
import respx
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey
from pydantic import AnyHttpUrl, SecretStr
from starlette.requests import Request

from authub.errors import InvalidStateError, ProtocolError
from authub.models import Connection, OidcSettings
from authub.protocols.oidc import OidcProtocol

ISSUER = "https://idp.test"
IDP_KEY = RSAKey.generate_key(2048, auto_kid=True)


def make_conn(**settings_overrides: Any) -> Connection:
    return Connection(
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
        conn=make_conn(), callback_url="http://app/auth/acme-oidc/callback", return_to="/x"
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
    begin = await protocol.begin(conn=make_conn(), callback_url="http://app/cb", return_to="/")
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
        request=request, conn=make_conn(), callback_url="http://app/cb", flow_state=state
    )
    assert raw.claims["sub"] == "user-1"
    assert raw.claims["email"] == "a@b.co"


@respx.mock
async def test_complete_rejects_state_mismatch() -> None:
    mock_discovery(respx.mock)
    protocol = OidcProtocol()
    begin = await protocol.begin(conn=make_conn(), callback_url="http://app/cb", return_to="/")
    request = get_request("http://app/cb?code=c1&state=WRONG")
    with pytest.raises(InvalidStateError):
        await protocol.complete(
            request=request,
            conn=make_conn(),
            callback_url="http://app/cb",
            flow_state=begin.flow_state,
        )


@respx.mock
async def test_complete_rejects_nonce_mismatch() -> None:
    mock_discovery(respx.mock)
    protocol = OidcProtocol()
    begin = await protocol.begin(conn=make_conn(), callback_url="http://app/cb", return_to="/")
    state = begin.flow_state
    respx.mock.post(f"{ISSUER}/token").respond(
        json={"access_token": "at", "id_token": make_id_token(nonce="EVIL")}
    )
    request = get_request(f"http://app/cb?code=c1&state={state.state}")
    with pytest.raises(ProtocolError):
        await protocol.complete(
            request=request, conn=make_conn(), callback_url="http://app/cb", flow_state=state
        )


@respx.mock
async def test_complete_rejects_expired_id_token() -> None:
    mock_discovery(respx.mock)
    protocol = OidcProtocol()
    begin = await protocol.begin(conn=make_conn(), callback_url="http://app/cb", return_to="/")
    state = begin.flow_state
    assert state.nonce
    expired = make_id_token(nonce=state.nonce, exp=int(time.time()) - 1000)
    respx.mock.post(f"{ISSUER}/token").respond(json={"access_token": "at", "id_token": expired})
    request = get_request(f"http://app/cb?code=c1&state={state.state}")
    with pytest.raises(ProtocolError):
        await protocol.complete(
            request=request, conn=make_conn(), callback_url="http://app/cb", flow_state=state
        )


@respx.mock
async def test_complete_rejects_wrong_audience() -> None:
    mock_discovery(respx.mock)
    protocol = OidcProtocol()
    begin = await protocol.begin(conn=make_conn(), callback_url="http://app/cb", return_to="/")
    state = begin.flow_state
    assert state.nonce
    respx.mock.post(f"{ISSUER}/token").respond(
        json={"access_token": "at", "id_token": make_id_token(nonce=state.nonce, aud="other")}
    )
    request = get_request(f"http://app/cb?code=c1&state={state.state}")
    with pytest.raises(ProtocolError):
        await protocol.complete(
            request=request, conn=make_conn(), callback_url="http://app/cb", flow_state=state
        )


@respx.mock
async def test_complete_surfaces_idp_error_param() -> None:
    mock_discovery(respx.mock)
    protocol = OidcProtocol()
    begin = await protocol.begin(conn=make_conn(), callback_url="http://app/cb", return_to="/")
    request = get_request("http://app/cb?error=access_denied")
    with pytest.raises(ProtocolError, match="access_denied"):
        await protocol.complete(
            request=request,
            conn=make_conn(),
            callback_url="http://app/cb",
            flow_state=begin.flow_state,
        )


@respx.mock
async def test_discovery_issuer_mismatch_rejected() -> None:
    respx.mock.get(f"{ISSUER}/.well-known/openid-configuration").respond(
        json={"issuer": "https://evil.test", "authorization_endpoint": f"{ISSUER}/a"}
    )
    protocol = OidcProtocol()
    with pytest.raises(ProtocolError, match="issuer"):
        await protocol.begin(conn=make_conn(), callback_url="http://app/cb", return_to="/")
