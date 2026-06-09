from __future__ import annotations

import base64
import binascii
import hashlib
import html
import secrets
import time
from collections.abc import Sequence
from functools import cached_property
from typing import Any
from urllib.parse import unquote, urlencode

from fastapi import APIRouter
from joserfc import jwt
from joserfc.jwk import KeySet, KeySetSerialization, RSAKey
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from authub.idp.models import AuthCode, IdpClient, IdpUser
from authub.idp.store import IdpUserStore, InMemoryIdpUserStore

_AUTHORIZE_FIELDS = (
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
)


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _login_form(action: str, params: dict[str, str], error: str | None) -> str:
    hidden = "\n".join(
        f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">'
        for k, v in params.items()
    )
    message = f"<p>{html.escape(error)}</p>" if error else ""
    return (
        "<!doctype html><html><body><h1>authub dev IdP</h1>"
        f'{message}<form method="post" action="{html.escape(action)}">{hidden}'
        '<label>Username <input name="username" autocomplete="username"></label>'
        '<label>Password <input name="password" type="password"></label>'
        '<button type="submit">Sign in</button></form></body></html>'
    )


class AuthubIdp:
    def __init__(
        self,
        *,
        issuer: str,
        clients: Sequence[IdpClient],
        users: IdpUserStore | None = None,
        auto_login: str | None = None,
        code_ttl_seconds: int = 60,
        token_ttl_seconds: int = 3600,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.users: IdpUserStore = users if users is not None else InMemoryIdpUserStore()
        self.auto_login = auto_login
        self._clients = {client.client_id: client for client in clients}
        self._key = RSAKey.generate_key(2048, auto_kid=True)
        self._codes: dict[str, AuthCode] = {}
        self._access_tokens: dict[str, tuple[str, int]] = {}
        self._code_ttl = code_ttl_seconds
        self._token_ttl = token_ttl_seconds

    def jwks(self) -> KeySetSerialization:
        return KeySet([self._key]).as_dict(private=False)

    def _validate_authorize_params(self, params: dict[str, str]) -> str | None:
        client = self._clients.get(params.get("client_id", ""))
        if client is None:
            return "unknown client_id"
        if params.get("redirect_uri", "") not in client.redirect_uris:
            return "redirect_uri is not registered for this client"
        if params.get("response_type") != "code":
            return "only response_type=code is supported"
        if "openid" not in params.get("scope", "").split():
            return "scope must include openid"
        challenge = params.get("code_challenge", "")
        if challenge and params.get("code_challenge_method") != "S256":
            return "only S256 code_challenge_method is supported"
        if client.client_secret is None and not challenge:
            return "public clients must use PKCE"
        return None

    def _issue_code_redirect(self, params: dict[str, str], user: IdpUser) -> RedirectResponse:
        code = secrets.token_urlsafe(32)
        self._codes[code] = AuthCode(
            code=code,
            client_id=params["client_id"],
            redirect_uri=params["redirect_uri"],
            scope=params.get("scope", ""),
            sub=user.sub,
            nonce=params.get("nonce") or None,
            code_challenge=params.get("code_challenge") or None,
            expires_at=int(time.time()) + self._code_ttl,
        )
        query: dict[str, str] = {"code": code}
        if params.get("state"):
            query["state"] = params["state"]
        return RedirectResponse(f"{params['redirect_uri']}?{urlencode(query)}", status_code=302)

    def _authenticate_client(self, request: Request, form: dict[str, str]) -> IdpClient | None:
        header = request.headers.get("authorization", "")
        if header.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(header[6:]).decode()
            except (binascii.Error, UnicodeDecodeError):
                return None
            client_id, _, client_secret = decoded.partition(":")
            client_id, client_secret = unquote(client_id), unquote(client_secret)
        else:
            client_id = form.get("client_id", "")
            client_secret = form.get("client_secret", "")
        client = self._clients.get(client_id)
        if client is None:
            return None
        if client.client_secret is None:
            return client
        if secrets.compare_digest(client.client_secret.get_secret_value(), client_secret):
            return client
        return None

    def _make_id_token(self, auth_code: AuthCode, user: IdpUser) -> str:
        now = int(time.time())
        payload: dict[str, Any] = {
            "iss": self.issuer,
            "sub": user.sub,
            "aud": auth_code.client_id,
            "iat": now,
            "exp": now + self._token_ttl,
            **user.claims,
        }
        if auth_code.nonce:
            payload["nonce"] = auth_code.nonce
        return jwt.encode(
            {"alg": "RS256", "kid": self._key.kid}, payload, self._key, algorithms=["RS256"]
        )

    @cached_property
    def router(self) -> APIRouter:
        router = APIRouter(tags=["dev-idp"])

        @router.get("/.well-known/openid-configuration")
        async def discovery() -> dict[str, Any]:
            return {
                "issuer": self.issuer,
                "authorization_endpoint": f"{self.issuer}/authorize",
                "token_endpoint": f"{self.issuer}/token",
                "jwks_uri": f"{self.issuer}/jwks",
                "userinfo_endpoint": f"{self.issuer}/userinfo",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "scopes_supported": ["openid", "email", "profile"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": [
                    "client_secret_basic",
                    "client_secret_post",
                ],
            }

        @router.get("/jwks")
        async def jwks() -> KeySetSerialization:
            return self.jwks()

        @router.get("/authorize")
        async def authorize(request: Request) -> Response:
            params = {k: request.query_params.get(k, "") for k in _AUTHORIZE_FIELDS}
            error = self._validate_authorize_params(params)
            if error is not None:
                return JSONResponse(
                    {"error": "invalid_request", "error_description": error},
                    status_code=400,
                )
            if self.auto_login is not None:
                user = await self._auto_login_user()
                if user is not None:
                    return self._issue_code_redirect(params, user)
            action = str(request.url_for("AuthubIdp_login"))
            return HTMLResponse(_login_form(action, params, error=None))

        @router.post("/login", name="AuthubIdp_login")
        async def login(request: Request) -> Response:
            form = {k: str(v) for k, v in (await request.form()).items()}
            params = {k: form.get(k, "") for k in _AUTHORIZE_FIELDS}
            error = self._validate_authorize_params(params)
            if error is not None:
                return JSONResponse(
                    {"error": "invalid_request", "error_description": error},
                    status_code=400,
                )
            user = await self.users.authenticate(form.get("username", ""), form.get("password", ""))
            if user is None:
                action = str(request.url_for("AuthubIdp_login"))
                return HTMLResponse(
                    _login_form(action, params, error="Wrong username or password"),
                    status_code=401,
                )
            return self._issue_code_redirect(params, user)

        @router.post("/token")
        async def token(request: Request) -> Response:
            form = {k: str(v) for k, v in (await request.form()).items()}
            client = self._authenticate_client(request, form)
            if client is None:
                return JSONResponse({"error": "invalid_client"}, status_code=401)
            if form.get("grant_type") != "authorization_code":
                return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

            auth_code = self._codes.pop(form.get("code", ""), None)
            if (
                auth_code is None
                or auth_code.expires_at <= int(time.time())
                or auth_code.client_id != client.client_id
                or auth_code.redirect_uri != form.get("redirect_uri", "")
            ):
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            if auth_code.code_challenge is not None:
                verifier = form.get("code_verifier", "")
                if not verifier or _s256(verifier) != auth_code.code_challenge:
                    return JSONResponse({"error": "invalid_grant"}, status_code=400)

            user = await self.users.get_by_sub(auth_code.sub)
            if user is None:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)

            access_token = secrets.token_urlsafe(32)
            self._access_tokens[access_token] = (user.sub, int(time.time()) + self._token_ttl)
            return JSONResponse(
                {
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": self._token_ttl,
                    "scope": auth_code.scope,
                    "id_token": self._make_id_token(auth_code, user),
                }
            )

        @router.get("/userinfo")
        async def userinfo(request: Request) -> Response:
            header = request.headers.get("authorization", "")
            token_value = header[7:].strip() if header.lower().startswith("bearer ") else ""
            entry = self._access_tokens.get(token_value)
            if entry is None or entry[1] <= int(time.time()):
                return JSONResponse({"error": "invalid_token"}, status_code=401)
            user = await self.users.get_by_sub(entry[0])
            if user is None:
                return JSONResponse({"error": "invalid_token"}, status_code=401)
            return JSONResponse({"sub": user.sub, **user.claims})

        return router

    async def _auto_login_user(self) -> IdpUser | None:
        if self.auto_login is None:
            return None
        return await self.users.get_by_username(self.auto_login)
