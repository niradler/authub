from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import Depends, FastAPI
from pydantic import SecretStr

from authub import Authub, Connection, Mapping, Principal, presets
from authub.idp import AuthubIdp, IdpClient, InMemoryIdpUserStore
from authub.stores.memory import InMemoryConnectionStore
from authub.tokens.jwt import JwtTokenService

ISSUER = "http://testserver/idp"


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    users = InMemoryIdpUserStore()
    users.add_user("alice", "wonderland", sub="alice-sub", email="alice@acme.example", name="Alice")
    idp = AuthubIdp(
        issuer=ISSUER,
        clients=[
            IdpClient(
                client_id="authub-app",
                client_secret=SecretStr("dev-secret"),
                redirect_uris=["http://testserver/auth/authub-idp/callback"],
            )
        ],
        users=users,
        auto_login="alice",
    )

    connections = InMemoryConnectionStore(
        [
            Connection(
                id="authub-idp",
                tenant_id="acme",
                display_name="Dev IdP",
                settings=presets.dev_idp(ISSUER, "authub-app", "dev-secret"),
                mapping=Mapping(),
            )
        ],
        domains={"acme.example": "acme"},
    )
    auth = Authub(
        connections=connections,
        tokens=JwtTokenService.ed25519(),
        state_secret="x" * 32,
    )

    app = FastAPI()
    auth.attach(app)
    app.include_router(idp.router, prefix="/idp")

    @app.get("/me")
    async def me(principal: Principal = Depends(auth.current_user)) -> Principal:  # noqa: B008
        return principal

    transport = httpx.ASGITransport(app=app)
    auth.http.transport = transport
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


async def test_full_login_journey(client: httpx.AsyncClient) -> None:
    discover = await client.get("/auth/discover", params={"email": "alice@acme.example"})
    assert discover.json()["connections"][0]["connection_id"] == "authub-idp"

    login = await client.get("/auth/authub-idp/login?return_to=/dash", follow_redirects=False)
    assert login.status_code == 302
    authorize_url = login.headers["location"]
    assert authorize_url.startswith(f"{ISSUER}/authorize?")

    at_idp = await client.get(authorize_url, follow_redirects=False)
    assert at_idp.status_code == 302
    callback_url = at_idp.headers["location"]
    assert callback_url.startswith("http://testserver/auth/authub-idp/callback")

    callback = await client.get(callback_url, follow_redirects=False)
    assert callback.status_code == 200, callback.text
    token = callback.json()["access_token"]

    me = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    body = me.json()
    assert body["email"] == "alice@acme.example"
    assert body["tenant_id"] == "acme"
    assert body["type"] == "user"


async def test_replayed_callback_fails(client: httpx.AsyncClient) -> None:
    login = await client.get("/auth/authub-idp/login", follow_redirects=False)
    at_idp = await client.get(login.headers["location"], follow_redirects=False)
    callback_url = at_idp.headers["location"]
    first = await client.get(callback_url, follow_redirects=False)
    assert first.status_code == 200
    second = await client.get(callback_url, follow_redirects=False)
    assert second.status_code == 400
