from __future__ import annotations

import secrets
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from authub.errors import AuthubError, InvalidStateError
from authub.models import ConnectionInfo
from authub.state import STATE_COOKIE
from authub.web.deps import extract_token

if TYPE_CHECKING:
    from authub.hub import Authub


def sanitize_return_to(value: str) -> str:
    if not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    return value


def callback_url_for(request: Request, hub: Authub, connection_id: str) -> str:
    url = str(request.url_for("authub_callback", connection_id=connection_id))
    if hub.public_base_url is not None:
        parts = urlsplit(url)
        base = urlsplit(hub.public_base_url)
        url = urlunsplit((base.scheme, base.netloc, parts.path, parts.query, parts.fragment))
    return url


async def authub_error_handler(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, AuthubError):
        raise exc
    return JSONResponse(
        {"error": exc.code, "error_description": exc.detail},
        status_code=exc.status_code,
    )


def build_router(hub: Authub) -> APIRouter:
    """Build the auth ``APIRouter`` with login, callback, logout, and discover endpoints.

    Prefer ``Authub.attach`` or the ``Authub.router`` property over calling this directly.
    """
    router = APIRouter(tags=["auth"])

    @router.get("/discover")
    async def discover(email: str) -> dict[str, list[ConnectionInfo]]:
        parts = email.split("@", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            return {"connections": []}
        return {"connections": await hub.connections.list_for_email(email)}

    @router.get("/{connection_id}/login", name="authub_login")
    async def login(request: Request, connection_id: str, return_to: str = "/") -> Response:
        result = await hub.flow.begin(
            connection_id=connection_id,
            callback_url=callback_url_for(request, hub, connection_id),
            return_to=sanitize_return_to(return_to),
        )
        response: Response = RedirectResponse(result.redirect_url, status_code=302)
        secure = request.url.scheme == "https"
        response.set_cookie(
            STATE_COOKIE,
            hub.state_codec.encode(result.flow_state),
            max_age=hub.state_codec.ttl_seconds,
            httponly=True,
            secure=secure,
            samesite="none" if secure else "lax",
            path="/",
        )
        return response

    @router.api_route("/{connection_id}/callback", methods=["GET", "POST"], name="authub_callback")
    async def callback(request: Request, connection_id: str) -> Response:
        raw_state = request.cookies.get(STATE_COOKIE)
        if not raw_state:
            raise InvalidStateError("login state cookie is missing or expired")
        flow_state = hub.state_codec.decode(raw_state)
        if flow_state.connection_id != connection_id:
            raise InvalidStateError("state was issued for a different connection")
        token, _principal = await hub.flow.complete(
            request=request,
            connection_id=connection_id,
            callback_url=callback_url_for(request, hub, connection_id),
            flow_state=flow_state,
        )
        config = hub.session_cookie
        if config is not None and config.success_redirect:
            response: Response = RedirectResponse(flow_state.return_to, status_code=303)
        else:
            response = JSONResponse({"access_token": token, "token_type": "bearer"})
        response.delete_cookie(STATE_COOKIE, path="/")
        if config is not None:
            response.set_cookie(
                config.cookie_name,
                token,
                max_age=config.max_age,
                httponly=True,
                secure=config.secure,
                samesite=config.samesite,
                path="/",
            )
            response.set_cookie(
                config.csrf_cookie_name,
                secrets.token_urlsafe(24),
                max_age=config.max_age,
                httponly=False,
                secure=config.secure,
                samesite=config.samesite,
                path="/",
            )
        return response

    @router.post("/logout")
    async def logout(request: Request) -> Response:
        if hub.revocation is not None:
            pair = extract_token(request, hub)
            if pair is not None:
                try:
                    claims = await hub.tokens.verify(pair[0])
                    await hub.revocation.revoke(claims.jti, claims.exp)
                except AuthubError:
                    pass
        response = JSONResponse({"ok": True})
        config = hub.session_cookie
        if config is not None:
            response.delete_cookie(config.cookie_name, path="/")
            response.delete_cookie(config.csrf_cookie_name, path="/")
        return response

    return router
