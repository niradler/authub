from __future__ import annotations

from joserfc import jwt
from joserfc.jwk import KeySet

from tests.conftest import (
    REDIRECT,
    exchange_code_for_tokens,
    get_code_via_login,
    make_bare_client,
    make_bare_idp,
    rotate_refresh,
    s256,
)


async def test_refresh_rotation_round_trip_full_e2e() -> None:
    """Code flow → refresh rotation → new tokens differ; new access token works at /userinfo."""
    idp, _ = make_bare_idp()
    async with make_bare_client(idp) as client:
        code = await get_code_via_login(client, scope="openid email offline_access")
        first = await exchange_code_for_tokens(client, code)

        assert "refresh_token" in first
        assert "access_token" in first
        assert "id_token" in first

        second_raw = await rotate_refresh(client, str(first["refresh_token"]))
        assert second_raw.get("access_token") is not None
        assert second_raw.get("refresh_token") is not None
        assert second_raw.get("id_token") is not None

        assert second_raw["access_token"] != first["access_token"]
        assert second_raw["refresh_token"] != first["refresh_token"]
        assert second_raw.get("scope") == "openid email offline_access"

        jwks_resp = await client.get("/idp/jwks")
        assert jwks_resp.status_code == 200
        key_set = KeySet.import_key_set(jwks_resp.json())
        decoded = jwt.decode(str(second_raw["id_token"]), key_set, algorithms=["RS256"])
        assert decoded.claims["sub"] is not None
        assert decoded.claims["iss"] == idp.issuer

        userinfo = await client.get(
            "/idp/userinfo",
            headers={"Authorization": f"Bearer {second_raw['access_token']}"},
        )
        assert userinfo.status_code == 200
        assert userinfo.json()["email"] == "alice@acme.test"


async def test_refresh_chain_three_rotations() -> None:
    """Rotate 3 times in a row; each new refresh works; each old one is dead."""
    idp, _ = make_bare_idp()
    async with make_bare_client(idp) as client:
        code = await get_code_via_login(client, scope="openid offline_access")
        tokens = await exchange_code_for_tokens(client, code)

        refresh_tokens: list[str] = [str(tokens["refresh_token"])]
        for _ in range(3):
            current_rt = refresh_tokens[-1]
            rotated = await rotate_refresh(client, current_rt)
            assert rotated.get("access_token") is not None, f"rotation failed: {rotated}"
            assert rotated.get("refresh_token") is not None
            refresh_tokens.append(str(rotated["refresh_token"]))

        for consumed_rt in refresh_tokens[:-1]:
            dead = await rotate_refresh(client, consumed_rt)
            assert dead.get("error") == "invalid_grant", f"consumed token should be dead: {dead}"


async def test_consent_approve_full_flow() -> None:
    """require_consent=True: login → consent approve → code → tokens issued."""
    import re

    idp, _ = make_bare_idp(require_consent=True)
    async with make_bare_client(idp) as client:
        params = {
            "response_type": "code",
            "client_id": "app",
            "redirect_uri": REDIRECT,
            "scope": "openid email",
            "state": "cs1",
            "nonce": "cn1",
            "code_challenge": s256("v" * 43),
            "code_challenge_method": "S256",
        }
        login = await client.post(
            "/idp/login",
            data={**params, "username": "alice", "password": "wonderland"},
        )
        assert login.status_code == 200
        ticket_match = re.search(r'name="ticket"\s+value="([^"]+)"', login.text)
        assert ticket_match is not None
        ticket = ticket_match.group(1)

        consent = await client.post(
            "/idp/consent",
            data={"ticket": ticket, "decision": "approve"},
            follow_redirects=False,
        )
        assert consent.status_code == 302
        location = consent.headers["location"]
        assert "code=" in location
        assert "state=cs1" in location

        code = location.split("code=")[1].split("&")[0]
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
        assert token_resp.status_code == 200
        body = token_resp.json()
        assert "access_token" in body
        assert "id_token" in body


async def test_consent_deny_preserves_state_no_code() -> None:
    """require_consent=True: deny → 302 with error=access_denied and original state."""
    import re

    idp, _ = make_bare_idp(require_consent=True)
    async with make_bare_client(idp) as client:
        params = {
            "response_type": "code",
            "client_id": "app",
            "redirect_uri": REDIRECT,
            "scope": "openid email",
            "state": "deny-st",
            "nonce": "dn1",
            "code_challenge": s256("v" * 43),
            "code_challenge_method": "S256",
        }
        login = await client.post(
            "/idp/login",
            data={**params, "username": "alice", "password": "wonderland"},
        )
        assert login.status_code == 200
        ticket_match = re.search(r'name="ticket"\s+value="([^"]+)"', login.text)
        assert ticket_match is not None
        ticket = ticket_match.group(1)

        deny = await client.post(
            "/idp/consent",
            data={"ticket": ticket, "decision": "deny"},
            follow_redirects=False,
        )
        assert deny.status_code == 302
        location = deny.headers["location"]
        assert location.startswith(REDIRECT)
        assert "error=access_denied" in location
        assert "state=deny-st" in location
        assert "code=" not in location


async def test_scope_filtered_userinfo_email_only() -> None:
    """scope=openid email → userinfo returns email+email_verified but not name."""
    idp, _ = make_bare_idp()
    async with make_bare_client(idp) as client:
        code = await get_code_via_login(client, scope="openid email")
        tokens = await exchange_code_for_tokens(client, code)
        access_token = str(tokens["access_token"])

        userinfo = await client.get(
            "/idp/userinfo", headers={"Authorization": f"Bearer {access_token}"}
        )
        assert userinfo.status_code == 200
        data = userinfo.json()
        assert "sub" in data
        assert data.get("email") == "alice@acme.test"
        assert "name" not in data
        assert "given_name" not in data


async def test_scope_filtered_userinfo_profile_only() -> None:
    """scope=openid profile → returns profile claims but NOT email."""
    idp, _ = make_bare_idp()
    async with make_bare_client(idp) as client:
        code = await get_code_via_login(client, scope="openid profile")
        tokens = await exchange_code_for_tokens(client, code)
        access_token = str(tokens["access_token"])

        userinfo = await client.get(
            "/idp/userinfo", headers={"Authorization": f"Bearer {access_token}"}
        )
        assert userinfo.status_code == 200
        data = userinfo.json()
        assert "sub" in data
        assert data.get("name") == "Alice"
        assert "email" not in data


async def test_scope_filtered_userinfo_openid_only() -> None:
    """scope=openid → only sub in userinfo response."""
    idp, _ = make_bare_idp()
    async with make_bare_client(idp) as client:
        code = await get_code_via_login(client, scope="openid")
        tokens = await exchange_code_for_tokens(client, code)
        access_token = str(tokens["access_token"])

        userinfo = await client.get(
            "/idp/userinfo", headers={"Authorization": f"Bearer {access_token}"}
        )
        assert userinfo.status_code == 200
        data = userinfo.json()
        assert "sub" in data
        assert "email" not in data
        assert "name" not in data


async def test_pkce_public_client_success() -> None:
    """Public client (no secret) with valid S256 PKCE verifier completes the full flow."""
    idp, _ = make_bare_idp(client_id="pubclient", client_secret=None)
    async with make_bare_client(idp) as client:
        verifier = "public-verifier-" + "a" * 30
        challenge = s256(verifier)
        params: dict[str, str] = {
            "response_type": "code",
            "client_id": "pubclient",
            "redirect_uri": REDIRECT,
            "scope": "openid email",
            "state": "pub-st",
            "nonce": "pub-n",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        login = await client.post(
            "/idp/login",
            data={**params, "username": "alice", "password": "wonderland"},
            follow_redirects=False,
        )
        assert login.status_code == 302, login.text
        code = login.headers["location"].split("code=")[1].split("&")[0]

        token_resp = await client.post(
            "/idp/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "code_verifier": verifier,
                "client_id": "pubclient",
            },
        )
        assert token_resp.status_code == 200
        body = token_resp.json()
        assert "access_token" in body
        assert "id_token" in body


async def test_pkce_public_client_wrong_verifier_rejected() -> None:
    """Public client with wrong code_verifier → 400 invalid_grant."""
    idp, _ = make_bare_idp(client_id="pubclient2", client_secret=None)
    async with make_bare_client(idp) as client:
        verifier = "correct-verifier-" + "b" * 28
        challenge = s256(verifier)
        params: dict[str, str] = {
            "response_type": "code",
            "client_id": "pubclient2",
            "redirect_uri": REDIRECT,
            "scope": "openid email",
            "state": "pk-st",
            "nonce": "pk-n",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        login = await client.post(
            "/idp/login",
            data={**params, "username": "alice", "password": "wonderland"},
            follow_redirects=False,
        )
        assert login.status_code == 302
        code = login.headers["location"].split("code=")[1].split("&")[0]

        wrong_verifier = "wrong-verifier-" + "c" * 30
        token_resp = await client.post(
            "/idp/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "code_verifier": wrong_verifier,
                "client_id": "pubclient2",
            },
        )
        assert token_resp.status_code == 400
        assert token_resp.json()["error"] == "invalid_grant"


async def test_id_token_rs256_decodable_from_jwks_endpoint() -> None:
    """id_token from code exchange is RS256-decodable against the live /idp/jwks endpoint."""
    idp, _ = make_bare_idp()
    async with make_bare_client(idp) as client:
        code = await get_code_via_login(client, scope="openid email")
        tokens = await exchange_code_for_tokens(client, code)

        jwks_resp = await client.get("/idp/jwks")
        assert jwks_resp.status_code == 200
        key_set = KeySet.import_key_set(jwks_resp.json())

        decoded = jwt.decode(str(tokens["id_token"]), key_set, algorithms=["RS256"])
        assert decoded.claims["iss"] == idp.issuer
        assert decoded.claims["aud"] == "app"
        assert decoded.claims["nonce"] == "n1"
