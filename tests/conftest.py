from __future__ import annotations

import base64
import hashlib
from collections.abc import AsyncIterator
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi import Depends, FastAPI
from pydantic import SecretStr

from authub import Authub, IdentityProvider, Mapping, Principal, presets
from authub.idp import AuthubIdp, IdpClient, IdpGrantStore, InMemoryIdpUserStore
from authub.stores.memory import InMemoryIdentityProviderStore
from authub.tokens.jwt import JwtTokenService

ISSUER = "http://testserver/idp"
REDIRECT = "http://app.test/cb"


def s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def make_bare_idp(
    *,
    client_id: str = "app",
    client_secret: str | None = "shh",
    redirect_uris: list[str] | None = None,
    auto_login: str | None = None,
    require_consent: bool = False,
    token_ttl_seconds: int = 3600,
    refresh_token_ttl_seconds: int = 1209600,
    code_ttl_seconds: int = 60,
    grants: IdpGrantStore | None = None,
) -> tuple[AuthubIdp, InMemoryIdpUserStore]:
    users = InMemoryIdpUserStore()
    users.add_user(
        "alice",
        "wonderland",
        sub="alice-sub",
        email="alice@acme.test",
        name="Alice",
        extra_claims={"email_verified": True},
    )
    secret = SecretStr(client_secret) if client_secret is not None else None
    idp = AuthubIdp(
        issuer=ISSUER,
        clients=[
            IdpClient(
                client_id=client_id,
                client_secret=secret,
                redirect_uris=redirect_uris or [REDIRECT],
            )
        ],
        users=users,
        auto_login=auto_login,
        require_consent=require_consent,
        token_ttl_seconds=token_ttl_seconds,
        refresh_token_ttl_seconds=refresh_token_ttl_seconds,
        code_ttl_seconds=code_ttl_seconds,
        grants=grants,
    )
    return idp, users


def make_bare_client(idp: AuthubIdp) -> httpx.AsyncClient:
    app = FastAPI()
    app.include_router(idp.router, prefix="/idp")
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


async def get_code_via_login(
    client: httpx.AsyncClient,
    *,
    scope: str = "openid email offline_access",
    username: str = "alice",
    password: str = "wonderland",
    client_id: str = "app",
    redirect_uri: str = REDIRECT,
    state: str = "st1",
    nonce: str = "n1",
    code_verifier: str = "v" * 43,
    extra_authorize: dict[str, str] | None = None,
) -> str:
    challenge = s256(code_verifier)
    params: dict[str, str] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        **(extra_authorize or {}),
    }
    login = await client.post(
        "/idp/login",
        data={**params, "username": username, "password": password},
        follow_redirects=False,
    )
    assert login.status_code == 302, login.text
    location = login.headers["location"]
    code = location.split("code=")[1].split("&")[0]
    return code


async def exchange_code_for_tokens(
    client: httpx.AsyncClient,
    code: str,
    *,
    client_id: str = "app",
    client_secret: str = "shh",
    redirect_uri: str = REDIRECT,
    code_verifier: str = "v" * 43,
) -> dict[str, object]:
    resp = await client.post(
        "/idp/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )
    assert resp.status_code == 200, resp.text
    result: dict[str, object] = resp.json()
    return result


async def rotate_refresh(
    client: httpx.AsyncClient,
    refresh_token: str,
    *,
    client_id: str = "app",
    client_secret: str = "shh",
    scope: str | None = None,
) -> dict[str, object]:
    data: dict[str, str] = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if scope is not None:
        data["scope"] = scope
    resp = await client.post("/idp/token", data=data)
    result: dict[str, object] = resp.json()
    return result


def parse_authorize_params_from_location(location: str) -> dict[str, str]:
    parts = urlsplit(location)
    return {k: v[0] for k, v in parse_qs(parts.query).items()}


@pytest.fixture
async def hub_client() -> AsyncIterator[tuple[httpx.AsyncClient, Authub]]:
    users = InMemoryIdpUserStore()
    users.add_user(
        "alice",
        "wonderland",
        sub="alice-sub",
        email="alice@acme.test",
        name="Alice",
        extra_claims={"email_verified": True},
    )
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
    )
    identity_providers = InMemoryIdentityProviderStore(
        [
            IdentityProvider(
                id="authub-idp",
                tenant_id="acme",
                display_name="Dev IdP",
                settings=presets.authub_idp(ISSUER, "authub-app", "dev-secret"),
                mapping=Mapping(),
            )
        ],
        domains={"acme.test": "acme"},
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
