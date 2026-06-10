from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from authub.hub import Authub
from authub.models import (
    IdentityProvider,
    OidcSettings,
    RawIdentity,
    SessionCookieConfig,
)
from authub.protocols.base import AuthProtocol
from authub.state import STATE_COOKIE, BeginResult, FlowState
from authub.stores.memory import InMemoryIdentityProviderStore
from authub.tokens.base import InMemoryRevocationStore
from authub.tokens.jwt import JwtTokenService
from authub.web.router import sanitize_return_to


class FakeProtocol(AuthProtocol):
    kind = "oidc"

    async def begin(self, *, idp: object, callback_url: object, return_to: object) -> BeginResult:
        return BeginResult(
            redirect_url=f"https://idp.test/authorize?cb={callback_url}",
            flow_state=FlowState(idp_id=idp.id, return_to=return_to),  # type: ignore[attr-defined, arg-type]
        )

    async def complete(
        self, *, request: object, idp: object, callback_url: object, flow_state: object
    ) -> RawIdentity:
        return RawIdentity(claims={"sub": "ext-1", "email": "a@b.co", "name": "Ada"})


def make_app(**hub_kwargs: object) -> tuple[FastAPI, Authub]:
    idp = IdentityProvider(
        id="acme-idp",
        tenant_id="acme",
        display_name="Acme IdP",
        settings=OidcSettings(
            issuer="https://idp.test",  # type: ignore[arg-type]
            client_id="c",
            client_secret=SecretStr("s"),
        ),
    )
    hub = Authub(
        identity_providers=InMemoryIdentityProviderStore([idp], domains={"acme.com": "acme"}),
        tokens=JwtTokenService.hs256("s" * 32),
        state_secret="x" * 32,
        **hub_kwargs,  # type: ignore[arg-type]
    )
    hub.registry.register(FakeProtocol())
    app = FastAPI()
    hub.attach(app)
    return app, hub


def client_for(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


def test_sanitize_return_to() -> None:
    assert sanitize_return_to("/app") == "/app"
    assert sanitize_return_to("//evil.com") == "/"
    assert sanitize_return_to("https://evil.com") == "/"
    assert sanitize_return_to("/a\\b") == "/"


async def test_login_redirects_and_sets_state_cookie() -> None:
    app, hub = make_app()
    async with client_for(app) as client:
        response = await client.get("/auth/acme-idp/login?return_to=/dash", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"].startswith("https://idp.test/authorize")
    assert "cb=http://testserver/auth/acme-idp/callback" in response.headers["location"]
    cookie = response.cookies.get(STATE_COOKIE)
    assert cookie
    state = hub.state_codec.decode(cookie)
    assert state.idp_id == "acme-idp" and state.return_to == "/dash"


async def test_login_unknown_connection_is_clean_404() -> None:
    app, _ = make_app()
    async with client_for(app) as client:
        response = await client.get("/auth/nope/login", follow_redirects=False)
    assert response.status_code == 404
    assert response.json() == {
        "error": "identity_provider_not_found",
        "error_description": "Unknown identity provider",
    }


async def test_callback_returns_token_json_and_clears_state_cookie() -> None:
    app, hub = make_app()
    async with client_for(app) as client:
        await client.get("/auth/acme-idp/login", follow_redirects=False)
        callback = await client.get(
            "/auth/acme-idp/callback?code=c&state=s", follow_redirects=False
        )
    assert callback.status_code == 200
    token = callback.json()["access_token"]
    claims = await hub.verify_token(token)
    assert claims.email == "a@b.co"
    set_cookie = callback.headers.get_list("set-cookie")
    assert any(
        STATE_COOKIE in v and ("Max-Age=0" in v or "expires" in v.lower()) for v in set_cookie
    )


async def test_callback_without_state_cookie_is_400() -> None:
    app, _ = make_app()
    async with client_for(app) as client:
        response = await client.get("/auth/acme-idp/callback?code=c")
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_state"


async def test_callback_connection_mismatch_rejected() -> None:
    app, hub = make_app()
    other_state = hub.state_codec.encode(FlowState(idp_id="other"))
    async with client_for(app) as client:
        client.cookies.set(STATE_COOKIE, other_state)
        response = await client.get("/auth/acme-idp/callback?code=c")
    assert response.status_code == 400


async def test_session_cookie_mode_redirects_and_sets_cookies() -> None:
    cfg = SessionCookieConfig(secure=False)
    app, _hub = make_app(session_cookie=cfg)
    async with client_for(app) as client:
        await client.get("/auth/acme-idp/login?return_to=/dash", follow_redirects=False)
        callback = await client.get(
            "/auth/acme-idp/callback?code=c&state=s", follow_redirects=False
        )
    assert callback.status_code == 303
    assert callback.headers["location"] == "/dash"
    assert callback.cookies.get(cfg.cookie_name)
    assert callback.cookies.get(cfg.csrf_cookie_name)


async def test_discover_uniform_shape() -> None:
    app, _ = make_app()
    async with client_for(app) as client:
        known = await client.get("/auth/discover", params={"email": "a@acme.com"})
        unknown = await client.get("/auth/discover", params={"email": "a@nope.io"})
    assert known.status_code == 200
    assert known.json()["identity_providers"][0]["idp_id"] == "acme-idp"
    assert unknown.status_code == 200
    assert unknown.json() == {"identity_providers": []}


async def test_discover_malformed_email_returns_200_empty() -> None:
    app, _ = make_app()
    async with client_for(app) as client:
        no_at = await client.get("/auth/discover", params={"email": "notanemail"})
        no_local = await client.get("/auth/discover", params={"email": "@domain.com"})
        no_domain = await client.get("/auth/discover", params={"email": "user@"})
    for response in (no_at, no_local, no_domain):
        assert response.status_code == 200
        assert response.json() == {"identity_providers": []}


async def test_logout_revokes_bearer_token() -> None:
    revocation = InMemoryRevocationStore()
    app, hub = make_app(revocation=revocation)
    async with client_for(app) as client:
        await client.get("/auth/acme-idp/login", follow_redirects=False)
        callback = await client.get(
            "/auth/acme-idp/callback?code=c&state=s", follow_redirects=False
        )
        token = callback.json()["access_token"]
        out = await client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert out.status_code == 200
    from authub.errors import TokenRevokedError

    with pytest.raises(TokenRevokedError):
        await hub.verify_token(token)


async def test_public_base_url_overrides_callback_host() -> None:
    app, _ = make_app(public_base_url="https://auth.example.com")
    async with client_for(app) as client:
        response = await client.get("/auth/acme-idp/login", follow_redirects=False)
    assert "cb=https://auth.example.com/auth/acme-idp/callback" in response.headers["location"]


async def test_session_cookie_logout_clears_both_cookies() -> None:
    """POST /auth/logout in cookie-session mode expires both the session and CSRF cookies."""
    cfg = SessionCookieConfig(secure=False)
    app, _hub = make_app(session_cookie=cfg)
    async with client_for(app) as client:
        # Complete a login so cookies are set
        await client.get("/auth/acme-idp/login?return_to=/dash", follow_redirects=False)
        callback = await client.get(
            "/auth/acme-idp/callback?code=c&state=s", follow_redirects=False
        )
        assert callback.status_code == 303
        session_token = client.cookies.get(cfg.cookie_name)
        csrf_token = client.cookies.get(cfg.csrf_cookie_name)
        assert session_token
        assert csrf_token

        # POST /auth/logout with the CSRF header to pass CSRF check
        out = await client.post(
            "/auth/logout",
            headers={cfg.csrf_header_name: csrf_token},
        )
    assert out.status_code == 200

    set_cookie_headers = out.headers.get_list("set-cookie")
    cookie_names_cleared = {cfg.cookie_name, cfg.csrf_cookie_name}
    for expected_name in cookie_names_cleared:
        assert any(
            expected_name in hdr and ("Max-Age=0" in hdr or "expires" in hdr.lower())
            for hdr in set_cookie_headers
        ), f"Expected {expected_name!r} to be cleared in Set-Cookie headers: {set_cookie_headers}"


async def test_idp_error_param_returns_400_protocol_error() -> None:
    """error= param in callback → 400 with error='protocol_error' JSON shape."""
    from starlette.requests import Request as StarletteRequest

    from authub.errors import ProtocolError

    class ErrorProtocol(FakeProtocol):
        async def complete(
            self, *, request: object, idp: object, callback_url: object, flow_state: object
        ) -> RawIdentity:
            if isinstance(request, StarletteRequest) and "error" in request.query_params:
                raise ProtocolError(
                    f"identity provider returned error: {request.query_params['error']}"
                )
            return RawIdentity(claims={"sub": "ext-1", "email": "a@b.co", "name": "Ada"})

    app, hub = make_app()
    hub.registry.register(ErrorProtocol())
    async with client_for(app) as client:
        await client.get("/auth/acme-idp/login", follow_redirects=False)
        response = await client.get(
            "/auth/acme-idp/callback?error=access_denied", follow_redirects=False
        )
    assert response.status_code == 400
    body = response.json()
    assert body["error"] == "protocol_error"


async def test_tampered_state_cookie_returns_400_invalid_state() -> None:
    """Garbage __authub_state cookie value → 400 with error='invalid_state'."""
    app, _ = make_app()
    async with client_for(app) as client:
        client.cookies.set(STATE_COOKIE, "totally.garbage.value")
        response = await client.get("/auth/acme-idp/callback?code=c&state=s")
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_state"
