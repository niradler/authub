from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest
import respx
from pydantic import AnyHttpUrl, SecretStr, TypeAdapter
from starlette.requests import Request

from authub.errors import InvalidStateError, ProtocolError
from authub.models import Connection, OAuth2Settings
from authub.protocols.oauth2 import OAuth2Protocol


def make_conn(userinfo: bool = True) -> Connection:
    return Connection(
        id="acme-gh",
        tenant_id="acme",
        display_name="GitHub",
        settings=OAuth2Settings(
            authorize_url=TypeAdapter(AnyHttpUrl).validate_python("https://gh.test/authorize"),
            token_url=TypeAdapter(AnyHttpUrl).validate_python("https://gh.test/token"),
            userinfo_url=TypeAdapter(AnyHttpUrl).validate_python("https://gh.test/user")
            if userinfo
            else None,
            client_id="cid",
            client_secret=SecretStr("cs"),
            scopes=["read:user"],
        ),
    )


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


async def test_begin_has_state_and_pkce() -> None:
    protocol = OAuth2Protocol()
    result = await protocol.begin(conn=make_conn(), callback_url="http://app/cb", return_to="/")
    query = parse_qs(urlsplit(result.redirect_url).query)
    assert query["state"] == [result.flow_state.state]
    assert query["code_challenge_method"] == ["S256"]
    assert result.flow_state.nonce is None


@respx.mock
async def test_complete_fetches_userinfo() -> None:
    respx.mock.post("https://gh.test/token").respond(
        json={"access_token": "at", "token_type": "bearer"}
    )
    respx.mock.get("https://gh.test/user").respond(
        json={"id": 42, "email": "a@b.co", "name": "Ada"}
    )
    protocol = OAuth2Protocol()
    begin = await protocol.begin(conn=make_conn(), callback_url="http://app/cb", return_to="/")
    request = get_request(f"http://app/cb?code=c1&state={begin.flow_state.state}")
    raw = await protocol.complete(
        request=request,
        conn=make_conn(),
        callback_url="http://app/cb",
        flow_state=begin.flow_state,
    )
    assert raw.claims["id"] == 42
    assert raw.claims["_oauth_token"]["access_token"] == "at"


@respx.mock
async def test_complete_without_userinfo_uses_token_response() -> None:
    respx.mock.post("https://gh.test/token").respond(json={"access_token": "at", "uid": "u9"})
    protocol = OAuth2Protocol()
    conn = make_conn(userinfo=False)
    begin = await protocol.begin(conn=conn, callback_url="http://app/cb", return_to="/")
    request = get_request(f"http://app/cb?code=c1&state={begin.flow_state.state}")
    raw = await protocol.complete(
        request=request, conn=conn, callback_url="http://app/cb", flow_state=begin.flow_state
    )
    assert raw.claims["uid"] == "u9"
    assert raw.claims["_oauth_token"]["access_token"] == "at"


async def test_complete_rejects_bad_state() -> None:
    protocol = OAuth2Protocol()
    begin = await protocol.begin(conn=make_conn(), callback_url="http://app/cb", return_to="/")
    request = get_request("http://app/cb?code=c1&state=NOPE")
    with pytest.raises(InvalidStateError):
        await protocol.complete(
            request=request,
            conn=make_conn(),
            callback_url="http://app/cb",
            flow_state=begin.flow_state,
        )


@respx.mock
async def test_userinfo_failure_is_protocol_error() -> None:
    respx.mock.post("https://gh.test/token").respond(json={"access_token": "at"})
    respx.mock.get("https://gh.test/user").respond(status_code=500)
    protocol = OAuth2Protocol()
    begin = await protocol.begin(conn=make_conn(), callback_url="http://app/cb", return_to="/")
    request = get_request(f"http://app/cb?code=c1&state={begin.flow_state.state}")
    with pytest.raises(ProtocolError):
        await protocol.complete(
            request=request,
            conn=make_conn(),
            callback_url="http://app/cb",
            flow_state=begin.flow_state,
        )
