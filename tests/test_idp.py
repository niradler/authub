from __future__ import annotations

import base64
import hashlib
import re
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
    require_consent: bool = False,
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
        require_consent=require_consent,
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


async def get_code_with_scope(client: httpx.AsyncClient, scope: str) -> str:
    params = {**AUTHORIZE_PARAMS, "scope": scope}
    login = await client.post(
        "/idp/login",
        data={**params, "username": "alice", "password": "wonderland"},
    )
    return login.headers["location"].split("code=")[1].split("&")[0]


async def exchange_code(
    client: httpx.AsyncClient, code: str, *, extra: dict[str, str] | None = None
) -> dict[str, object]:
    data: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT,
        "code_verifier": "v" * 43,
        "client_id": "app",
        "client_secret": "shh",
        **(extra or {}),
    }
    resp = await client.post("/idp/token", data=data)
    result: dict[str, object] = resp.json()
    return result


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


# ---------------------------------------------------------------------------
# Feature A: refresh-token rotation with reuse detection
# ---------------------------------------------------------------------------


async def test_offline_access_scope_yields_refresh_token() -> None:
    async with make_client(make_idp()) as client:
        code = await get_code_with_scope(client, "openid email offline_access")
        payload = await exchange_code(client, code)
    assert "refresh_token" in payload
    assert isinstance(payload["refresh_token"], str)


async def test_no_offline_access_no_refresh_token() -> None:
    async with make_client(make_idp()) as client:
        code = await get_code_with_scope(client, "openid email")
        payload = await exchange_code(client, code)
    assert "refresh_token" not in payload


async def test_refresh_grant_returns_new_tokens() -> None:
    idp = make_idp()
    async with make_client(idp) as client:
        code = await get_code_with_scope(client, "openid email offline_access")
        first = await exchange_code(client, code)
        assert "refresh_token" in first

        refresh_resp = await client.post(
            "/idp/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": first["refresh_token"],
                "client_id": "app",
                "client_secret": "shh",
            },
        )
    assert refresh_resp.status_code == 200
    second = refresh_resp.json()
    assert "access_token" in second
    assert "refresh_token" in second
    assert "id_token" in second
    assert second["access_token"] != first["access_token"]
    assert second["refresh_token"] != first["refresh_token"]

    jwks = KeySet.import_key_set(idp.jwks())
    decoded = jwt.decode(second["id_token"], jwks, algorithms=["RS256"])
    assert decoded.claims["sub"] is not None


async def test_refresh_token_reuse_revokes_family() -> None:
    async with make_client(make_idp()) as client:
        code = await get_code_with_scope(client, "openid offline_access")
        first = await exchange_code(client, code)
        original_rt = first["refresh_token"]

        rotate_resp = await client.post(
            "/idp/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": original_rt,
                "client_id": "app",
                "client_secret": "shh",
            },
        )
        assert rotate_resp.status_code == 200
        rotated = rotate_resp.json()
        new_rt = rotated["refresh_token"]

        replay_resp = await client.post(
            "/idp/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": original_rt,
                "client_id": "app",
                "client_secret": "shh",
            },
        )
        assert replay_resp.status_code == 400
        assert replay_resp.json()["error"] == "invalid_grant"

        family_revoked_resp = await client.post(
            "/idp/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": new_rt,
                "client_id": "app",
                "client_secret": "shh",
            },
        )
        assert family_revoked_resp.status_code == 400
        assert family_revoked_resp.json()["error"] == "invalid_grant"


async def test_refresh_token_wrong_client_rejected() -> None:
    users = InMemoryIdpUserStore()
    users.add_user("alice", "wonderland", email="alice@acme.test", name="Alice")
    idp = AuthubIdp(
        issuer=ISSUER,
        clients=[
            IdpClient(client_id="app", client_secret=SecretStr("shh"), redirect_uris=[REDIRECT]),
            IdpClient(
                client_id="other",
                client_secret=SecretStr("othersecret"),
                redirect_uris=[REDIRECT],
            ),
        ],
        users=users,
    )
    async with make_client(idp) as client:
        code = await get_code_with_scope(client, "openid offline_access")
        first = await exchange_code(client, code)
        rt = first["refresh_token"]

        wrong_client_resp = await client.post(
            "/idp/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": rt,
                "client_id": "other",
                "client_secret": "othersecret",
            },
        )
    assert wrong_client_resp.status_code == 400
    assert wrong_client_resp.json()["error"] == "invalid_grant"


async def test_refresh_token_scope_narrowing_works() -> None:
    async with make_client(make_idp()) as client:
        code = await get_code_with_scope(client, "openid email offline_access")
        first = await exchange_code(client, code)
        rt = first["refresh_token"]

        resp = await client.post(
            "/idp/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": rt,
                "scope": "openid",
                "client_id": "app",
                "client_secret": "shh",
            },
        )
    assert resp.status_code == 200
    assert resp.json()["scope"] == "openid"


async def test_refresh_token_scope_broadening_rejected() -> None:
    async with make_client(make_idp()) as client:
        code = await get_code_with_scope(client, "openid offline_access")
        first = await exchange_code(client, code)
        rt = first["refresh_token"]

        resp = await client.post(
            "/idp/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": rt,
                "scope": "openid email profile",
                "client_id": "app",
                "client_secret": "shh",
            },
        )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_scope"


# ---------------------------------------------------------------------------
# Feature B: userinfo scope filtering
# ---------------------------------------------------------------------------


async def test_userinfo_openid_only_returns_sub_only() -> None:
    async with make_client(make_idp()) as client:
        code = await get_code_with_scope(client, "openid")
        payload = await exchange_code(client, code)
        access_token = payload["access_token"]
        userinfo = await client.get(
            "/idp/userinfo", headers={"Authorization": f"Bearer {access_token}"}
        )
    data = userinfo.json()
    assert "sub" in data
    assert "email" not in data
    assert "name" not in data


async def test_userinfo_email_scope_adds_email() -> None:
    async with make_client(make_idp()) as client:
        code = await get_code_with_scope(client, "openid email")
        payload = await exchange_code(client, code)
        access_token = payload["access_token"]
        userinfo = await client.get(
            "/idp/userinfo", headers={"Authorization": f"Bearer {access_token}"}
        )
    data = userinfo.json()
    assert data["email"] == "alice@acme.test"
    assert "name" not in data


async def test_userinfo_profile_scope_adds_name() -> None:
    async with make_client(make_idp()) as client:
        code = await get_code_with_scope(client, "openid email profile")
        payload = await exchange_code(client, code)
        access_token = payload["access_token"]
        userinfo = await client.get(
            "/idp/userinfo", headers={"Authorization": f"Bearer {access_token}"}
        )
    data = userinfo.json()
    assert data["email"] == "alice@acme.test"
    assert data["name"] == "Alice"


# ---------------------------------------------------------------------------
# Feature C: optional consent screen
# ---------------------------------------------------------------------------


def _extract_consent_ticket(html: str) -> str:
    """Pull the ticket value out of the consent form hidden input."""
    m = re.search(r'name="ticket"\s+value="([^"]+)"', html)
    assert m is not None, "consent form has no ticket field"
    return m.group(1)


def _extract_form_action(html: str) -> str:
    m = re.search(r'<form[^>]+action="([^"]+)"', html)
    assert m is not None, "no form action found"
    return m.group(1)


async def test_consent_disabled_login_still_302s() -> None:
    """Default (require_consent=False) preserves the existing redirect behaviour."""
    async with make_client(make_idp()) as client:
        r = await client.post(
            "/idp/login",
            data={**AUTHORIZE_PARAMS, "username": "alice", "password": "wonderland"},
        )
    assert r.status_code == 302
    assert r.headers["location"].startswith(REDIRECT)


async def test_consent_login_returns_200_html_not_302() -> None:
    """With require_consent=True a successful login shows the consent form, not a redirect."""
    async with make_client(make_idp(require_consent=True)) as client:
        r = await client.post(
            "/idp/login",
            data={**AUTHORIZE_PARAMS, "username": "alice", "password": "wonderland"},
        )
    assert r.status_code == 200
    assert "app" in r.text
    for scope_token in AUTHORIZE_PARAMS["scope"].split():
        assert scope_token in r.text
    assert "location" not in r.headers


async def test_consent_form_contains_ticket_and_client_id_and_scopes() -> None:
    async with make_client(make_idp(require_consent=True)) as client:
        r = await client.post(
            "/idp/login",
            data={**AUTHORIZE_PARAMS, "username": "alice", "password": "wonderland"},
        )
    assert r.status_code == 200
    assert "app" in r.text
    assert "openid" in r.text
    assert "email" in r.text
    assert "profile" in r.text
    ticket = _extract_consent_ticket(r.text)
    assert len(ticket) > 20


async def test_consent_approve_issues_exchangeable_code() -> None:
    """Approving consent → 302 with code → exchangeable at /token."""
    idp = make_idp(require_consent=True)
    async with make_client(idp) as client:
        login = await client.post(
            "/idp/login",
            data={**AUTHORIZE_PARAMS, "username": "alice", "password": "wonderland"},
        )
        assert login.status_code == 200
        ticket = _extract_consent_ticket(login.text)

        consent = await client.post(
            "/idp/consent",
            data={"ticket": ticket, "decision": "approve"},
        )
    assert consent.status_code == 302
    location = consent.headers["location"]
    assert location.startswith(REDIRECT)
    assert "code=" in location
    assert "state=st1" in location

    code = location.split("code=")[1].split("&")[0]
    async with make_client(idp) as client2:
        token_resp = await client2.post(
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
    assert token_resp.status_code == 200
    assert "id_token" in token_resp.json()


async def test_consent_deny_redirects_with_access_denied_and_preserves_state() -> None:
    async with make_client(make_idp(require_consent=True)) as client:
        login = await client.post(
            "/idp/login",
            data={**AUTHORIZE_PARAMS, "username": "alice", "password": "wonderland"},
        )
        ticket = _extract_consent_ticket(login.text)

        deny = await client.post(
            "/idp/consent",
            data={"ticket": ticket, "decision": "deny"},
        )
    assert deny.status_code == 302
    location = deny.headers["location"]
    assert location.startswith(REDIRECT)
    assert "error=access_denied" in location
    assert "state=st1" in location
    assert "code=" not in location


async def test_consent_tampered_ticket_returns_400() -> None:
    async with make_client(make_idp(require_consent=True)) as client:
        r = await client.post(
            "/idp/consent",
            data={"ticket": "this.is.garbage", "decision": "approve"},
        )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_request"


async def test_consent_auto_login_shows_consent_form() -> None:
    """With require_consent=True, auto_login triggers consent form instead of code redirect."""
    async with make_client(make_idp(auto_login="alice", require_consent=True)) as client:
        r = await client.get("/idp/authorize", params=AUTHORIZE_PARAMS, follow_redirects=False)
    assert r.status_code == 200
    assert "app" in r.text
    ticket = _extract_consent_ticket(r.text)
    assert len(ticket) > 20


async def test_consent_auto_login_approve_gives_code() -> None:
    idp = make_idp(auto_login="alice", require_consent=True)
    async with make_client(idp) as client:
        authorize = await client.get(
            "/idp/authorize", params=AUTHORIZE_PARAMS, follow_redirects=False
        )
        assert authorize.status_code == 200
        ticket = _extract_consent_ticket(authorize.text)

        consent = await client.post(
            "/idp/consent",
            data={"ticket": ticket, "decision": "approve"},
        )
    assert consent.status_code == 302
    assert "code=" in consent.headers["location"]
