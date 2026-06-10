from __future__ import annotations

import base64
import hashlib
import time

import httpx
import pytest
from fastapi import FastAPI
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey
from pydantic import SecretStr

from authub.idp.models import IdpClient
from authub.idp.provider import AuthubIdp
from authub.idp.store import (
    IdpGrantStore,
    InMemoryIdpGrantStore,
    InMemoryIdpUserStore,
    hash_password,
    verify_password,
)

ISSUER = "http://testserver/idp"
REDIRECT = "http://app.test/cb"


def make_idp(
    auto_login: str | None = None,
    *,
    grants: IdpGrantStore | None = None,
    signing_key: str | RSAKey | None = None,
    max_login_attempts: int = 5,
    lockout_seconds: int = 300,
) -> AuthubIdp:
    users = InMemoryIdpUserStore()
    users.add_user("alice", "wonderland", email="alice@acme.test", name="Alice")
    return AuthubIdp(
        issuer=ISSUER,
        clients=[
            IdpClient(client_id="app", client_secret=SecretStr("shh"), redirect_uris=[REDIRECT])
        ],
        users=users,
        auto_login=auto_login,
        grants=grants,
        signing_key=signing_key,
        max_login_attempts=max_login_attempts,
        lockout_seconds=lockout_seconds,
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


async def test_login_form_heading_is_authub_idp() -> None:
    async with make_client(make_idp()) as client:
        response = await client.get("/idp/authorize", params=AUTHORIZE_PARAMS)
    assert "authub IdP" in response.text
    assert "dev IdP" not in response.text


async def test_default_sub_prefix_is_authub() -> None:
    users = InMemoryIdpUserStore()
    user = users.add_user("bob", "pw")
    assert user.sub.startswith("authub|")


async def test_router_tag_is_authub_idp() -> None:
    idp = make_idp()
    routes = idp.router.routes
    for route in routes:
        for tag in getattr(route, "tags", []):
            assert tag != "dev-idp"
    assert (
        any(tag == "authub-idp" for route in routes for tag in getattr(route, "tags", []))
        or "authub-idp" in idp.router.tags
    )


async def test_injectable_signing_key_jwks_match() -> None:
    pem_key = RSAKey.generate_key(2048, auto_kid=True)
    pem = pem_key.as_pem(private=True).decode()

    idp1 = make_idp(signing_key=pem)
    idp2 = make_idp(signing_key=pem)

    assert idp1.jwks() == idp2.jwks()


async def test_injectable_signing_key_cross_validate() -> None:
    pem = RSAKey.generate_key(2048, auto_kid=True).as_pem(private=True).decode()

    idp1 = make_idp(signing_key=pem)
    idp2 = make_idp(signing_key=pem)

    async with make_client(idp1) as client:
        code = await get_code(client)
        token_resp = await client.post(
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
    id_token = token_resp.json()["id_token"]

    jwks2 = KeySet.import_key_set(idp2.jwks())
    decoded = jwt.decode(id_token, jwks2, algorithms=["RS256"])
    assert decoded.claims["iss"] == ISSUER


async def test_injectable_signing_key_as_rsakey_object() -> None:
    rsa_key = RSAKey.generate_key(2048, auto_kid=True)
    idp1 = make_idp(signing_key=rsa_key)
    idp2 = make_idp(signing_key=rsa_key)
    assert idp1.jwks() == idp2.jwks()


async def test_injectable_signing_key_without_kid_gets_kid() -> None:
    pem_key = RSAKey.generate_key(2048, auto_kid=True)
    pem = pem_key.as_pem(private=True).decode()

    pem_key_no_kid = RSAKey.import_key(pem)
    assert pem_key_no_kid.kid is None

    idp = make_idp(signing_key=pem)
    assert idp._key.kid is not None


async def test_grant_store_injectable() -> None:
    store = InMemoryIdpGrantStore()
    idp = make_idp(grants=store)

    async with make_client(idp) as client:
        code = await get_code(client)
        resp = await client.post(
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
    assert resp.status_code == 200


async def test_grant_store_abc_subclassable() -> None:
    assert issubclass(InMemoryIdpGrantStore, IdpGrantStore)


async def test_brute_force_lockout_after_max_attempts() -> None:
    idp = make_idp(max_login_attempts=3, lockout_seconds=300)
    async with make_client(idp) as client:
        for _ in range(3):
            r = await client.post(
                "/idp/login",
                data={**AUTHORIZE_PARAMS, "username": "alice", "password": "wrong"},
            )
            assert r.status_code == 401

        locked = await client.post(
            "/idp/login",
            data={**AUTHORIZE_PARAMS, "username": "alice", "password": "wrong"},
        )
    assert locked.status_code == 429
    assert "Too many attempts" in locked.text


async def test_brute_force_lockout_correct_password_still_blocked() -> None:
    idp = make_idp(max_login_attempts=2, lockout_seconds=300)
    async with make_client(idp) as client:
        for _ in range(2):
            await client.post(
                "/idp/login",
                data={**AUTHORIZE_PARAMS, "username": "alice", "password": "wrong"},
            )

        still_blocked = await client.post(
            "/idp/login",
            data={**AUTHORIZE_PARAMS, "username": "alice", "password": "wonderland"},
        )
    assert still_blocked.status_code == 429


async def test_brute_force_clears_after_window(monkeypatch: pytest.MonkeyPatch) -> None:
    idp = make_idp(max_login_attempts=2, lockout_seconds=10)
    real_time = time.time
    async with make_client(idp) as client:
        for _ in range(2):
            await client.post(
                "/idp/login",
                data={**AUTHORIZE_PARAMS, "username": "alice", "password": "wrong"},
            )

        locked = await client.post(
            "/idp/login",
            data={**AUTHORIZE_PARAMS, "username": "alice", "password": "wrong"},
        )
        assert locked.status_code == 429

        monkeypatch.setattr("authub.idp.provider.time.time", lambda: real_time() + 11)

        unlocked = await client.post(
            "/idp/login",
            data={**AUTHORIZE_PARAMS, "username": "alice", "password": "wonderland"},
        )
    assert unlocked.status_code == 302


async def test_successful_login_clears_failure_counter() -> None:
    idp = make_idp(max_login_attempts=3, lockout_seconds=300)
    async with make_client(idp) as client:
        for _ in range(2):
            await client.post(
                "/idp/login",
                data={**AUTHORIZE_PARAMS, "username": "alice", "password": "wrong"},
            )

        ok = await client.post(
            "/idp/login",
            data={**AUTHORIZE_PARAMS, "username": "alice", "password": "wonderland"},
        )
        assert ok.status_code == 302

        code = ok.headers["location"].split("code=")[1].split("&")[0]
        await client.post(
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

        still_ok = await client.post(
            "/idp/login",
            data={**AUTHORIZE_PARAMS, "username": "alice", "password": "wonderland"},
        )
    assert still_ok.status_code == 302
