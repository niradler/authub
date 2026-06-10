from __future__ import annotations

import re
import time

from joserfc import jwt
from joserfc.jwk import RSAKey

from authub.idp import InMemoryIdpGrantStore
from tests.conftest import (
    REDIRECT,
    exchange_code_for_tokens,
    get_code_via_login,
    make_bare_client,
    make_bare_idp,
    rotate_refresh,
    s256,
)


async def test_refresh_reuse_revokes_family() -> None:
    """R0 → rotate to R1 → replay R0 → 400; R1 is also dead (family revoked)."""
    idp, _ = make_bare_idp()
    async with make_bare_client(idp) as client:
        code = await get_code_via_login(client, scope="openid offline_access")
        first = await exchange_code_for_tokens(client, code)
        r0 = str(first["refresh_token"])

        second = await rotate_refresh(client, r0)
        assert second.get("access_token") is not None
        r1 = str(second["refresh_token"])

        replay = await rotate_refresh(client, r0)
        assert replay.get("error") == "invalid_grant"

        r1_attempt = await rotate_refresh(client, r1)
        assert r1_attempt.get("error") == "invalid_grant"


async def test_cross_client_refresh_rejected() -> None:
    """Refresh token issued to client A, presented with client B credentials → 400 invalid_grant."""
    from pydantic import SecretStr

    from authub.idp import AuthubIdp, IdpClient, InMemoryIdpUserStore

    users = InMemoryIdpUserStore()
    users.add_user("alice", "wonderland", sub="alice-sub", email="alice@acme.test", name="Alice")
    idp = AuthubIdp(
        issuer="http://testserver/idp",
        clients=[
            IdpClient(client_id="app", client_secret=SecretStr("shh"), redirect_uris=[REDIRECT]),
            IdpClient(
                client_id="other",
                client_secret=SecretStr("other-shh"),
                redirect_uris=[REDIRECT],
            ),
        ],
        users=users,
    )
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(idp.router, prefix="/idp")
    import httpx

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        code = await get_code_via_login(client, scope="openid offline_access")
        first = await exchange_code_for_tokens(client, code)
        rt = str(first["refresh_token"])

        cross = await rotate_refresh(client, rt, client_id="other", client_secret="other-shh")
        assert cross.get("error") == "invalid_grant"


async def test_scope_escalation_on_refresh_blocked() -> None:
    """Requesting superset scope on refresh → 400 invalid_scope."""
    idp, _ = make_bare_idp()
    async with make_bare_client(idp) as client:
        code = await get_code_via_login(client, scope="openid offline_access")
        first = await exchange_code_for_tokens(client, code)
        rt = str(first["refresh_token"])

        escalated = await rotate_refresh(client, rt, scope="openid offline_access email")
        assert escalated.get("error") == "invalid_scope"


async def test_scope_narrowing_on_refresh_succeeds() -> None:
    """Requesting subset scope on refresh → succeeds with narrowed scope."""
    idp, _ = make_bare_idp()
    async with make_bare_client(idp) as client:
        code = await get_code_via_login(client, scope="openid email offline_access")
        first = await exchange_code_for_tokens(client, code)
        rt = str(first["refresh_token"])

        narrowed = await rotate_refresh(client, rt, scope="openid")
        assert narrowed.get("error") is None
        assert narrowed.get("scope") == "openid"


async def test_garbage_bearer_at_userinfo_returns_401() -> None:
    """Random garbage bearer → 401 invalid_token."""
    idp, _ = make_bare_idp()
    async with make_bare_client(idp) as client:
        resp = await client.get(
            "/idp/userinfo", headers={"Authorization": "Bearer totallygarbage.jwt.token"}
        )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_token"


async def test_expired_access_token_at_userinfo_returns_401() -> None:
    """Access token with past expiry → 401 invalid_token (injected directly into grant store)."""
    grant_store = InMemoryIdpGrantStore()
    idp, _ = make_bare_idp(grants=grant_store)
    async with make_bare_client(idp) as client:
        expired_token = "expired-token-value-abc123"
        expired_at = int(time.time()) - 1
        await grant_store.save_access_token(expired_token, "alice-sub", expired_at, "openid")

        resp = await client.get(
            "/idp/userinfo", headers={"Authorization": f"Bearer {expired_token}"}
        )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_token"


async def test_tampered_consent_ticket_wrong_key_returns_400() -> None:
    """Consent ticket signed by a different RSA key → 400 invalid_request."""
    different_key = RSAKey.generate_key(2048, auto_kid=True)

    forged_ticket = jwt.encode(
        {"alg": "RS256", "kid": different_key.kid},
        {
            "iss": "http://testserver/idp",
            "sub": "alice-sub",
            "purpose": "consent",
            "params": {
                "response_type": "code",
                "client_id": "app",
                "redirect_uri": REDIRECT,
                "scope": "openid",
                "state": "st1",
                "nonce": "n1",
                "code_challenge": s256("v" * 43),
                "code_challenge_method": "S256",
            },
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
        },
        different_key,
        algorithms=["RS256"],
    )

    idp, _ = make_bare_idp(require_consent=True)
    async with make_bare_client(idp) as client:
        resp = await client.post(
            "/idp/consent",
            data={"ticket": forged_ticket, "decision": "approve"},
        )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


async def test_open_redirect_unregistered_redirect_uri_returns_400() -> None:
    """/authorize with redirect_uri not in registered list → 400, no redirect to attacker URI."""
    idp, _ = make_bare_idp()
    async with make_bare_client(idp) as client:
        resp = await client.get(
            "/idp/authorize",
            params={
                "response_type": "code",
                "client_id": "app",
                "redirect_uri": "http://attacker.evil/steal",
                "scope": "openid",
                "state": "evil-state",
                "nonce": "n",
                "code_challenge": s256("v" * 43),
                "code_challenge_method": "S256",
            },
        )
    assert resp.status_code == 400
    assert "location" not in resp.headers or not resp.headers.get("location", "").startswith(
        "http://attacker.evil"
    )


async def test_open_redirect_redirect_uri_mismatch_at_token_exchange() -> None:
    """redirect_uri in token exchange differs from the one in the code → 400 invalid_grant."""
    idp, _ = make_bare_idp()
    async with make_bare_client(idp) as client:
        code = await get_code_via_login(client, scope="openid email", redirect_uri=REDIRECT)

        resp = await client.post(
            "/idp/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://other-app.test/callback",
                "code_verifier": "v" * 43,
                "client_id": "app",
                "client_secret": "shh",
            },
        )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


async def test_token_request_wrong_client_secret_returns_401() -> None:
    """/token with incorrect client_secret → 401 invalid_client."""
    idp, _ = make_bare_idp()
    async with make_bare_client(idp) as client:
        code = await get_code_via_login(client, scope="openid email")

        resp = await client.post(
            "/idp/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "code_verifier": "v" * 43,
                "client_id": "app",
                "client_secret": "WRONG-SECRET",
            },
        )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


async def test_token_request_no_auth_returns_401() -> None:
    """/token with no client credentials at all → 401 invalid_client."""
    idp, _ = make_bare_idp()
    async with make_bare_client(idp) as client:
        code = await get_code_via_login(client, scope="openid email")

        resp = await client.post(
            "/idp/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "code_verifier": "v" * 43,
            },
        )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


async def test_public_client_without_pkce_rejected_at_authorize() -> None:
    """Public client (no secret) without PKCE → 400 at /authorize, not at /token."""
    idp, _ = make_bare_idp(client_id="pub-no-pkce", client_secret=None)
    async with make_bare_client(idp) as client:
        resp = await client.get(
            "/idp/authorize",
            params={
                "response_type": "code",
                "client_id": "pub-no-pkce",
                "redirect_uri": REDIRECT,
                "scope": "openid",
                "state": "st1",
                "nonce": "n1",
            },
        )
    assert resp.status_code == 400


async def test_no_access_token_header_at_userinfo_returns_401() -> None:
    """No Authorization header at /userinfo → 401 invalid_token."""
    idp, _ = make_bare_idp()
    async with make_bare_client(idp) as client:
        resp = await client.get("/idp/userinfo")
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_token"


_AUTHORIZE_PARAMS_CONSENT = {
    "response_type": "code",
    "client_id": "app",
    "redirect_uri": REDIRECT,
    "scope": "openid",
    "state": "st1",
    "nonce": "n1",
    "code_challenge": s256("v" * 43),
    "code_challenge_method": "S256",
}


async def _get_consent_ticket(client: object) -> str:
    import httpx

    assert isinstance(client, httpx.AsyncClient)
    login = await client.post(
        "/idp/login",
        data={**_AUTHORIZE_PARAMS_CONSENT, "username": "alice", "password": "wonderland"},
    )
    assert login.status_code == 200, login.text
    m = re.search(r'name="ticket" value="([^"]+)"', login.text)
    assert m is not None, "consent form has no ticket field"
    return m.group(1)


async def test_consent_ticket_single_use_replay_rejected() -> None:
    """A consent ticket used once (approve) cannot be replayed for a second code."""
    idp, _ = make_bare_idp(require_consent=True)
    async with make_bare_client(idp) as client:
        ticket = await _get_consent_ticket(client)

        first = await client.post(
            "/idp/consent",
            data={"ticket": ticket, "decision": "approve"},
        )
        assert first.status_code == 302
        assert "code=" in first.headers["location"]

        second = await client.post(
            "/idp/consent",
            data={"ticket": ticket, "decision": "approve"},
        )
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_request"
    assert "code=" not in second.headers.get("location", "")


async def test_consent_ticket_consumed_even_on_deny() -> None:
    """A consent ticket used for deny cannot be replayed for approve."""
    idp, _ = make_bare_idp(require_consent=True)
    async with make_bare_client(idp) as client:
        ticket = await _get_consent_ticket(client)

        deny = await client.post(
            "/idp/consent",
            data={"ticket": ticket, "decision": "deny"},
        )
        assert deny.status_code == 302
        assert "error=access_denied" in deny.headers["location"]

        replay = await client.post(
            "/idp/consent",
            data={"ticket": ticket, "decision": "approve"},
        )
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_request"
    assert "code=" not in replay.headers.get("location", "")
