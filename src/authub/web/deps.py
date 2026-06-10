from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Literal

from fastapi import HTTPException
from starlette.requests import Request

from authub.errors import AuthubError
from authub.models import Principal, PrincipalType

if TYPE_CHECKING:
    from authub.hub import Authub

TokenSource = Literal["header", "cookie"]
PrincipalDependency = Callable[[Request], Awaitable[Principal]]
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def extract_token(request: Request, hub: Authub) -> tuple[str, TokenSource] | None:
    """Extract a bearer token from the ``Authorization`` header or session cookie.

    Returns ``(token, source)`` or ``None`` when no token is present.
    """
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip(), "header"
    config = hub.session_cookie
    if config is not None:
        cookie = request.cookies.get(config.cookie_name)
        if cookie:
            return cookie, "cookie"
    return None


def _unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(401, detail, headers={"WWW-Authenticate": "Bearer"})


def _enforce_csrf(request: Request, hub: Authub) -> None:
    config = hub.session_cookie
    if config is None:
        return
    header = request.headers.get(config.csrf_header_name, "")
    cookie = request.cookies.get(config.csrf_cookie_name, "")
    if not cookie or not secrets.compare_digest(header, cookie):
        raise HTTPException(403, "CSRF check failed")


def make_principal_dependency(
    hub: Authub, require_type: PrincipalType | None = None
) -> PrincipalDependency:
    """Build a FastAPI dependency that verifies a JWT and optionally enforces principal type.

    Raises HTTP 401 when no token is present or the token is invalid, and HTTP 403 when the
    principal type does not match. Enforces CSRF on cookie-sourced tokens for mutating methods.
    """

    async def dependency(request: Request) -> Principal:
        pair = extract_token(request, hub)
        if pair is None:
            raise _unauthorized()
        token, source = pair
        try:
            claims = await hub.verify_token(token)
        except AuthubError as exc:
            raise _unauthorized("Invalid token") from exc
        if require_type is not None and claims.token_type is not require_type:
            raise HTTPException(403, "Wrong principal type")
        if source == "cookie" and request.method not in _SAFE_METHODS:
            _enforce_csrf(request, hub)
        return claims.to_principal()

    return dependency


def make_scopes_dependency(hub: Authub, scopes: tuple[str, ...]) -> PrincipalDependency:
    """Require ALL of the given scopes."""
    base = make_principal_dependency(hub)

    async def dependency(request: Request) -> Principal:
        principal = await base(request)
        if any(scope not in principal.scopes for scope in scopes):
            raise HTTPException(403, "Insufficient scope")
        return principal

    return dependency


def make_roles_dependency(hub: Authub, roles: tuple[str, ...]) -> PrincipalDependency:
    """Require ANY of the given roles."""
    base = make_principal_dependency(hub, require_type=PrincipalType.USER)

    async def dependency(request: Request) -> Principal:
        principal = await base(request)
        if not any(role in principal.roles for role in roles):
            raise HTTPException(403, "Insufficient role")
        return principal

    return dependency
