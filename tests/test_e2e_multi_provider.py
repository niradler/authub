from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi import Depends, FastAPI
from pydantic import SecretStr

from authub import Authub, IdentityProvider, Mapping, Principal, presets
from authub.idp import AuthubIdp, IdpClient, InMemoryIdpUserStore
from authub.state import STATE_COOKIE
from authub.stores.memory import InMemoryIdentityProviderStore
from authub.tokens.jwt import JwtTokenService

ISSUER = "http://testserver/idp"


@pytest.fixture
async def multi_client() -> AsyncIterator[tuple[httpx.AsyncClient, Authub]]:
    users = InMemoryIdpUserStore()
    users.add_user("alice", "pw", sub="alice-sub", email="alice@acme.example", name="Alice")
    users.add_user("bob", "pw", sub="bob-sub", email="bob@globex.example", name="Bob")

    idp = AuthubIdp(
        issuer=ISSUER,
        clients=[
            IdpClient(
                client_id="acme-client",
                client_secret=SecretStr("acme-secret"),
                redirect_uris=["http://testserver/auth/acme-conn/callback"],
            ),
            IdpClient(
                client_id="globex-client",
                client_secret=SecretStr("globex-secret"),
                redirect_uris=["http://testserver/auth/globex-conn/callback"],
            ),
        ],
        users=users,
    )

    identity_providers = InMemoryIdentityProviderStore(
        [
            IdentityProvider(
                id="acme-conn",
                tenant_id="acme",
                display_name="Acme IdP",
                settings=presets.authub_idp(ISSUER, "acme-client", "acme-secret"),
                mapping=Mapping(),
            ),
            IdentityProvider(
                id="globex-conn",
                tenant_id="globex",
                display_name="Globex IdP",
                settings=presets.authub_idp(ISSUER, "globex-client", "globex-secret"),
                mapping=Mapping(),
            ),
        ],
        domains={"acme.example": "acme", "globex.example": "globex"},
    )
    auth = Authub(
        identity_providers=identity_providers,
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
        yield c, auth


async def _run_login_flow(
    client: httpx.AsyncClient, idp_id: str, username: str, password: str
) -> dict[str, object]:
    """Drive a full credential login through the given identity provider and return the /me body."""
    login = await client.get(f"/auth/{idp_id}/login", follow_redirects=False)
    assert login.status_code == 302
    authorize_url = login.headers["location"]

    parts = urlsplit(authorize_url)
    authorize_params = {k: v[0] for k, v in parse_qs(parts.query).items()}

    login_post = await client.post(
        "/idp/login",
        data={**authorize_params, "username": username, "password": password},
        follow_redirects=False,
    )
    assert login_post.status_code == 302, login_post.text
    callback_url = login_post.headers["location"]

    callback = await client.get(callback_url, follow_redirects=False)
    assert callback.status_code == 200, callback.text
    token = callback.json()["access_token"]

    me = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    return dict(me.json())


async def test_two_tenants_complete_independently(
    multi_client: tuple[httpx.AsyncClient, Authub],
) -> None:
    """Both identity providers complete full credential logins; tokens carry tenant and user."""
    client, _auth = multi_client
    acme_me = await _run_login_flow(client, "acme-conn", "alice", "pw")
    globex_me = await _run_login_flow(client, "globex-conn", "bob", "pw")

    assert acme_me["tenant_id"] == "acme"
    assert acme_me["email"] == "alice@acme.example"
    assert globex_me["tenant_id"] == "globex"
    assert globex_me["email"] == "bob@globex.example"


async def test_tenant_ids_are_distinct(
    multi_client: tuple[httpx.AsyncClient, Authub],
) -> None:
    """acme token cannot claim globex tenant and vice-versa; users are also distinct."""
    client, _auth = multi_client
    acme_me = await _run_login_flow(client, "acme-conn", "alice", "pw")
    globex_me = await _run_login_flow(client, "globex-conn", "bob", "pw")

    assert acme_me["tenant_id"] != globex_me["tenant_id"]
    assert acme_me["email"] != globex_me["email"]


async def test_state_cookie_for_connection_a_rejected_at_connection_b_callback(
    multi_client: tuple[httpx.AsyncClient, Authub],
) -> None:
    """A state cookie issued for acme-conn must be rejected at globex-conn's callback."""
    client, _auth = multi_client

    # Start a login for acme-conn — this sets the state cookie for "acme-conn"
    login = await client.get("/auth/acme-conn/login", follow_redirects=False)
    assert login.status_code == 302
    # The state cookie is now in client.cookies for __authub_state
    state_cookie = client.cookies.get(STATE_COOKIE)
    assert state_cookie, "state cookie must be set after /login"

    # Attempt to complete via globex-conn — must be rejected (identity provider mismatch)
    response = await client.get("/auth/globex-conn/callback?code=fake&state=fake")
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_state"
