from __future__ import annotations

import time
from datetime import timedelta

import httpx
from fastapi import Depends, FastAPI

from authub.hub import Authub
from authub.models import (
    CanonicalIdentity,
    Principal,
    PrincipalType,
    SessionCookieConfig,
)
from authub.stores.memory import InMemoryConnectionStore
from authub.tokens.claims import build_user_claims
from authub.tokens.jwt import JwtTokenService

SECRET = "s" * 32


def make_app(session_cookie: SessionCookieConfig | None = None) -> tuple[FastAPI, Authub]:
    hub = Authub(
        connections=InMemoryConnectionStore(),
        tokens=JwtTokenService.hs256(SECRET),
        state_secret="x" * 32,
        session_cookie=session_cookie,
    )
    app = FastAPI()

    @app.get("/me")
    async def me(principal: Principal = Depends(hub.current_user)) -> Principal:  # noqa: B008
        return principal

    @app.get("/any")
    async def any_principal(p: Principal = Depends(hub.current_principal)) -> Principal:  # noqa: B008
        return p

    @app.get("/scoped")
    async def scoped(p: Principal = Depends(hub.require_scopes("builds:read"))) -> Principal:  # noqa: B008
        return p

    @app.get("/admin")
    async def admin(p: Principal = Depends(hub.require_roles("admin"))) -> Principal:  # noqa: B008
        return p

    @app.post("/mutate")
    async def mutate(p: Principal = Depends(hub.current_user)) -> dict[str, bool]:  # noqa: B008
        return {"ok": True}

    return app, hub


async def make_user_token(hub: Authub, **overrides: object) -> str:
    principal = Principal(
        id="u1",
        type=PrincipalType.USER,
        tenant_id="t",
        roles=list(overrides.pop("roles", [])),  # type: ignore[call-overload]
        scopes=list(overrides.pop("scopes", [])),  # type: ignore[call-overload]
    )
    claims = build_user_claims(
        principal, CanonicalIdentity(external_id="x", raw={}), timedelta(hours=1)
    )
    return await hub.tokens.sign(claims)


def client_for(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


async def test_bearer_happy_path() -> None:
    app, hub = make_app()
    token = await make_user_token(hub)
    async with client_for(app) as client:
        response = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["id"] == "u1"


async def test_missing_token_is_401_with_www_authenticate() -> None:
    app, _ = make_app()
    async with client_for(app) as client:
        response = await client.get("/me")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


async def test_garbage_token_is_401() -> None:
    app, _ = make_app()
    async with client_for(app) as client:
        response = await client.get("/me", headers={"Authorization": "Bearer junk"})
    assert response.status_code == 401


async def test_service_token_rejected_by_current_user_allowed_by_current_principal() -> None:
    app, hub = make_app()
    svc = Principal(id="s1", type=PrincipalType.SERVICE, tenant_id="t")
    token = await hub.issue_service_token(svc)
    async with client_for(app) as client:
        me = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
        anyp = await client.get("/any", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 403
    assert anyp.status_code == 200


async def test_scopes_enforced() -> None:
    app, hub = make_app()
    svc = Principal(id="s1", type=PrincipalType.SERVICE, tenant_id="t", scopes=["builds:read"])
    good = await hub.issue_service_token(svc)
    bad = await hub.issue_service_token(
        Principal(id="s2", type=PrincipalType.SERVICE, tenant_id="t")
    )
    async with client_for(app) as client:
        ok = await client.get("/scoped", headers={"Authorization": f"Bearer {good}"})
        deny = await client.get("/scoped", headers={"Authorization": f"Bearer {bad}"})
    assert ok.status_code == 200
    assert deny.status_code == 403


async def test_roles_enforced() -> None:
    app, hub = make_app()
    token = await make_user_token(hub, roles=["admin"])
    plain = await make_user_token(hub)
    async with client_for(app) as client:
        ok = await client.get("/admin", headers={"Authorization": f"Bearer {token}"})
        deny = await client.get("/admin", headers={"Authorization": f"Bearer {plain}"})
    assert ok.status_code == 200
    assert deny.status_code == 403


async def test_cookie_session_and_csrf() -> None:
    cfg = SessionCookieConfig(secure=False)
    app, hub = make_app(session_cookie=cfg)
    token = await make_user_token(hub)
    cookies = {cfg.cookie_name: token, cfg.csrf_cookie_name: "csrf-1"}
    async with client_for(app) as client:
        read = await client.get("/me", cookies=cookies)
        no_csrf = await client.post("/mutate", cookies=cookies)
        with_csrf = await client.post(
            "/mutate", cookies=cookies, headers={cfg.csrf_header_name: "csrf-1"}
        )
        wrong_csrf = await client.post(
            "/mutate", cookies=cookies, headers={cfg.csrf_header_name: "evil"}
        )
    assert read.status_code == 200
    assert no_csrf.status_code == 403
    assert with_csrf.status_code == 200
    assert wrong_csrf.status_code == 403


async def test_bearer_requests_skip_csrf() -> None:
    cfg = SessionCookieConfig(secure=False)
    app, hub = make_app(session_cookie=cfg)
    token = await make_user_token(hub)
    async with client_for(app) as client:
        response = await client.post("/mutate", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


async def test_expired_token_returns_401() -> None:
    """A token whose exp is in the past is rejected with 401."""
    app, hub = make_app()
    principal = Principal(
        id="u-expired",
        type=PrincipalType.USER,
        tenant_id="t",
    )
    identity = CanonicalIdentity(external_id="x", raw={})
    # Build claims with a TTL that places exp in the past
    claims = build_user_claims(principal, identity, timedelta(seconds=1))
    # Force exp to be 120 seconds in the past (exceeds the 60-second leeway in JwtTokenService)
    claims["exp"] = int(time.time()) - 120
    token = await hub.tokens.sign(claims)
    async with client_for(app) as client:
        response = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
