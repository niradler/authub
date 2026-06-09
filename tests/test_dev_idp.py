from __future__ import annotations

import base64
import hashlib

import httpx
from fastapi import FastAPI
from joserfc import jwt
from joserfc.jwk import KeySet
from pydantic import SecretStr

from authub.idp.models import IdpClient
from authub.idp.provider import AuthubIdp
from authub.idp.store import InMemoryIdpUserStore, hash_password, verify_password

ISSUER = "http://testserver/idp"
REDIRECT = "http://app.test/cb"


def make_idp(auto_login: str | None = None) -> AuthubIdp:
    users = InMemoryIdpUserStore()
    users.add_user("alice", "wonderland", email="alice@acme.test", name="Alice")
    return AuthubIdp(
        issuer=ISSUER,
        clients=[
            IdpClient(client_id="app", client_secret=SecretStr("shh"), redirect_uris=[REDIRECT])
        ],
        users=users,
        auto_login=auto_login,
    )


def make_client(idp: AuthubIdp) -> httpx.AsyncClient:
    app = FastAPI()
    app.include_router(idp.router, prefix="/idp")
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


def s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


AUTHORIZE_PARAMS = {
    "response_type": "code",
    "client_id": "app",
    "redirect_uri": REDIRECT,
    "scope": "openid email profile",
    "state": "st1",
    "nonce": "n1",
    "code_challenge": s256("v" * 43),
    "code_challenge_method": "S256",
}


def test_password_hashing_roundtrip() -> None:
    hashed = hash_password("pw")
    assert verify_password("pw", hashed)
    assert not verify_password("nope", hashed)
    assert hashed != hash_password("pw")


async def test_discovery_document() -> None:
    async with make_client(make_idp()) as client:
        response = await client.get("/idp/.well-known/openid-configuration")
    doc = response.json()
    assert doc["issuer"] == ISSUER
    assert doc["authorization_endpoint"] == f"{ISSUER}/authorize"
    assert doc["token_endpoint"] == f"{ISSUER}/token"
    assert doc["jwks_uri"] == f"{ISSUER}/jwks"
    assert "S256" in doc["code_challenge_methods_supported"]


async def test_full_code_flow_with_login_form() -> None:
    idp = make_idp()
    async with make_client(idp) as client:
        authorize = await client.get("/idp/authorize", params=AUTHORIZE_PARAMS)
        assert authorize.status_code == 200
        assert "password" in authorize.text

        login = await client.post(
            "/idp/login",
            data={**AUTHORIZE_PARAMS, "username": "alice", "password": "wonderland"},
        )
        assert login.status_code == 302
        location = login.headers["location"]
        assert location.startswith(REDIRECT)
        assert "state=st1" in location
        code = location.split("code=")[1].split("&")[0]

        token_response = await client.post(
            "/idp/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "code_verifier": "v" * 43,
                "client_id": "app",
                "client_secret": "shh",
            },
        )
    assert token_response.status_code == 200
    payload = token_response.json()
    assert payload["token_type"] == "Bearer"

    jwks = KeySet.import_key_set(idp.jwks())
    decoded = jwt.decode(payload["id_token"], jwks, algorithms=["RS256"])
    assert decoded.claims["iss"] == ISSUER
    assert decoded.claims["aud"] == "app"
    assert decoded.claims["nonce"] == "n1"
    assert decoded.claims["email"] == "alice@acme.test"


async def test_auto_login_skips_form() -> None:
    async with make_client(make_idp(auto_login="alice")) as client:
        response = await client.get(
            "/idp/authorize", params=AUTHORIZE_PARAMS, follow_redirects=False
        )
    assert response.status_code == 302
    assert response.headers["location"].startswith(REDIRECT)


async def test_wrong_password_rerenders_form_401() -> None:
    async with make_client(make_idp()) as client:
        response = await client.post(
            "/idp/login",
            data={**AUTHORIZE_PARAMS, "username": "alice", "password": "wrong"},
        )
    assert response.status_code == 401


async def test_unregistered_redirect_uri_rejected_without_redirect() -> None:
    async with make_client(make_idp()) as client:
        response = await client.get(
            "/idp/authorize",
            params={**AUTHORIZE_PARAMS, "redirect_uri": "http://evil.test/cb"},
        )
    assert response.status_code == 400


async def get_code(client: httpx.AsyncClient) -> str:
    login = await client.post(
        "/idp/login",
        data={**AUTHORIZE_PARAMS, "username": "alice", "password": "wonderland"},
    )
    return login.headers["location"].split("code=")[1].split("&")[0]


async def test_code_is_single_use() -> None:
    async with make_client(make_idp()) as client:
        code = await get_code(client)
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": "v" * 43,
            "client_id": "app",
            "client_secret": "shh",
        }
        first = await client.post("/idp/token", data=data)
        second = await client.post("/idp/token", data=data)
    assert first.status_code == 200
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_grant"


async def test_pkce_mismatch_rejected() -> None:
    async with make_client(make_idp()) as client:
        code = await get_code(client)
        response = await client.post(
            "/idp/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "code_verifier": "w" * 43,
                "client_id": "app",
                "client_secret": "shh",
            },
        )
    assert response.status_code == 400


async def test_bad_client_secret_rejected() -> None:
    async with make_client(make_idp()) as client:
        code = await get_code(client)
        response = await client.post(
            "/idp/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "code_verifier": "v" * 43,
                "client_id": "app",
                "client_secret": "WRONG",
            },
        )
    assert response.status_code == 401


async def test_userinfo_with_access_token() -> None:
    async with make_client(make_idp()) as client:
        code = await get_code(client)
        token_response = await client.post(
            "/idp/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "code_verifier": "v" * 43,
                "client_id": "app",
                "client_secret": "shh",
            },
        )
        access_token = token_response.json()["access_token"]
        userinfo = await client.get(
            "/idp/userinfo", headers={"Authorization": f"Bearer {access_token}"}
        )
        bad = await client.get("/idp/userinfo", headers={"Authorization": "Bearer junk"})
    assert userinfo.json()["email"] == "alice@acme.test"
    assert bad.status_code == 401
