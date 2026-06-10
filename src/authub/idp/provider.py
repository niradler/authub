from __future__ import annotations

import base64
import binascii
import hashlib
import html
import logging
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

from authub.idp.models import AuthCode, IdpClient, IdpUser, RefreshToken
from authub.idp.store import (
    IdpGrantStore,
    IdpUserStore,
    InMemoryIdpGrantStore,
    InMemoryIdpUserStore,
    RefreshRotateOutcome,
)

logger = logging.getLogger(__name__)

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


_SCOPE_CLAIM_MAP: dict[str, tuple[str, ...]] = {
    "email": ("email", "email_verified"),
    "profile": ("name", "given_name", "family_name", "preferred_username", "picture"),
}


def _filter_claims_by_scope(claims: dict[str, Any], scope: str) -> dict[str, Any]:
    """Return a subset of claims permitted by the granted scope.

    Always includes sub when present. Scope tokens not in _SCOPE_CLAIM_MAP contribute nothing.
    openid is the required base scope and grants only sub (which is handled at the call site).
    """
    scopes = set(scope.split())
    result: dict[str, Any] = {}
    for scope_name, claim_names in _SCOPE_CLAIM_MAP.items():
        if scope_name in scopes:
            for claim in claim_names:
                if claim in claims:
                    result[claim] = claims[claim]
    return result


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
        "<!doctype html><html><body><h1>authub IdP</h1>"
        f'{message}<form method="post" action="{html.escape(action)}">{hidden}'
        '<label>Username <input name="username" autocomplete="username"></label>'
        '<label>Password <input name="password" type="password"></label>'
        '<button type="submit">Sign in</button></form></body></html>'
    )


class AuthubIdp:
    """Embedded OIDC authorization server.

    Implements the authorization code flow with PKCE and optional client secret auth.
    Suitable for production use when configured with a persistent signing_key,
    a durable IdpUserStore, and (for multi-instance) a durable IdpGrantStore.
    """

    def __init__(
        self,
        *,
        issuer: str,
        clients: Sequence[IdpClient],
        users: IdpUserStore | None = None,
        grants: IdpGrantStore | None = None,
        signing_key: str | RSAKey | None = None,
        auto_login: str | None = None,
        code_ttl_seconds: int = 60,
        token_ttl_seconds: int = 3600,
        refresh_token_ttl_seconds: int = 1209600,
        max_login_attempts: int = 5,
        lockout_seconds: int = 300,
    ) -> None:
        """Create an AuthubIdp instance.

        Args:
            issuer: Base URL of this IdP (no trailing slash).
            clients: Registered OIDC clients.
            users: User store. Defaults to InMemoryIdpUserStore.
            grants: Grant/token store. Defaults to InMemoryIdpGrantStore.
            signing_key: PEM string or RSAKey for signing JWTs. None generates
                an ephemeral key (restarts invalidate existing tokens).
            auto_login: Username to authenticate without showing the login form.
            code_ttl_seconds: Authorization code lifetime in seconds.
            token_ttl_seconds: Access/ID token lifetime in seconds.
            refresh_token_ttl_seconds: Refresh token lifetime in seconds. Defaults to 14 days.
            max_login_attempts: Failed attempts before a username is locked out.
            lockout_seconds: How long a locked-out username must wait.
        """
        self.issuer = issuer.rstrip("/")
        self.users: IdpUserStore = users if users is not None else InMemoryIdpUserStore()
        self._grants: IdpGrantStore = grants if grants is not None else InMemoryIdpGrantStore()
        self._clients = {client.client_id: client for client in clients}
        self._key = self._resolve_signing_key(signing_key)
        self.auto_login = auto_login
        self._code_ttl = code_ttl_seconds
        self._token_ttl = token_ttl_seconds
        self._refresh_token_ttl = refresh_token_ttl_seconds
        self._max_attempts = max_login_attempts
        self._lockout_seconds = lockout_seconds
        self._login_failures: dict[str, tuple[int, float]] = {}

    @staticmethod
    def _resolve_signing_key(signing_key: str | RSAKey | None) -> RSAKey:
        if signing_key is None:
            return RSAKey.generate_key(2048, auto_kid=True)
        if isinstance(signing_key, RSAKey):
            key = signing_key
        else:
            key = RSAKey.import_key(
                signing_key.encode() if isinstance(signing_key, str) else signing_key
            )
        if key.kid is None:
            key.ensure_kid()
        return key

    def jwks(self) -> KeySetSerialization:
        """Return the public JWKS for this IdP."""
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

    def _is_locked_out(self, username: str) -> bool:
        entry = self._login_failures.get(username)
        if entry is None:
            return False
        count, window_start = entry
        if time.time() - window_start >= self._lockout_seconds:
            del self._login_failures[username]
            return False
        return count >= self._max_attempts

    def _record_failure(self, username: str) -> None:
        entry = self._login_failures.get(username)
        now = time.time()
        if entry is None or now - entry[1] >= self._lockout_seconds:
            self._login_failures[username] = (1, now)
        else:
            self._login_failures[username] = (entry[0] + 1, entry[1])

    def _clear_failures(self, username: str) -> None:
        self._login_failures.pop(username, None)

    def _evict_stale_lockouts(self) -> None:
        now = time.time()
        stale = [
            u for u, (_, ts) in self._login_failures.items() if now - ts >= self._lockout_seconds
        ]
        for u in stale:
            del self._login_failures[u]

    async def _issue_code_redirect(self, params: dict[str, str], user: IdpUser) -> RedirectResponse:
        code = secrets.token_urlsafe(32)
        auth_code = AuthCode(
            code=code,
            client_id=params["client_id"],
            redirect_uri=params["redirect_uri"],
            scope=params.get("scope", ""),
            sub=user.sub,
            nonce=params.get("nonce") or None,
            code_challenge=params.get("code_challenge") or None,
            expires_at=int(time.time()) + self._code_ttl,
        )
        await self._grants.save_code(auth_code)
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

    def _make_refresh_id_token(self, rt: RefreshToken, user: IdpUser) -> str:
        now = int(time.time())
        payload: dict[str, Any] = {
            "iss": self.issuer,
            "sub": user.sub,
            "aud": rt.client_id,
            "iat": now,
            "exp": now + self._token_ttl,
            **user.claims,
        }
        return jwt.encode(
            {"alg": "RS256", "kid": self._key.kid}, payload, self._key, algorithms=["RS256"]
        )

    @cached_property
    def router(self) -> APIRouter:
        router = APIRouter(tags=["authub-idp"])

        @router.get("/.well-known/openid-configuration")
        async def discovery() -> dict[str, Any]:
            return {
                "issuer": self.issuer,
                "authorization_endpoint": f"{self.issuer}/authorize",
                "token_endpoint": f"{self.issuer}/token",
                "jwks_uri": f"{self.issuer}/jwks",
                "userinfo_endpoint": f"{self.issuer}/userinfo",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "scopes_supported": ["openid", "email", "profile", "offline_access"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": [
                    "client_secret_basic",
                    "client_secret_post",
                ],
            }

        @router.get("/jwks")
        async def jwks() -> JSONResponse:
            return JSONResponse(dict(self.jwks()))

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
                    return await self._issue_code_redirect(params, user)
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
            username = form.get("username", "")
            self._evict_stale_lockouts()
            if self._is_locked_out(username):
                action = str(request.url_for("AuthubIdp_login"))
                return HTMLResponse(
                    _login_form(action, params, error="Too many attempts, try again later"),
                    status_code=429,
                )
            user = await self.users.authenticate(username, form.get("password", ""))
            if user is None:
                self._record_failure(username)
                action = str(request.url_for("AuthubIdp_login"))
                return HTMLResponse(
                    _login_form(action, params, error="Wrong username or password"),
                    status_code=401,
                )
            self._clear_failures(username)
            return await self._issue_code_redirect(params, user)

        @router.post("/token")
        async def token(request: Request) -> Response:
            form = {k: str(v) for k, v in (await request.form()).items()}
            client = self._authenticate_client(request, form)
            if client is None:
                return JSONResponse({"error": "invalid_client"}, status_code=401)

            grant_type = form.get("grant_type", "")

            if grant_type == "authorization_code":
                return await _handle_authorization_code(client, form)
            if grant_type == "refresh_token":
                return await _handle_refresh_token(client, form)
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

        async def _handle_authorization_code(client: IdpClient, form: dict[str, str]) -> Response:
            auth_code = await self._grants.consume_code(form.get("code", ""))
            if (
                auth_code is None
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
            await self._grants.save_access_token(
                access_token, user.sub, int(time.time()) + self._token_ttl, auth_code.scope
            )
            body: dict[str, Any] = {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": self._token_ttl,
                "scope": auth_code.scope,
                "id_token": self._make_id_token(auth_code, user),
            }
            if "offline_access" in auth_code.scope.split():
                rt = RefreshToken(
                    token=secrets.token_urlsafe(32),
                    sub=user.sub,
                    client_id=client.client_id,
                    scope=auth_code.scope,
                    family_id=secrets.token_urlsafe(16),
                    expires_at=int(time.time()) + self._refresh_token_ttl,
                )
                await self._grants.save_refresh_token(rt)
                body["refresh_token"] = rt.token
            return JSONResponse(body)

        async def _handle_refresh_token(client: IdpClient, form: dict[str, str]) -> Response:
            token_str = form.get("refresh_token", "")
            outcome, rt = await self._grants.rotate_refresh_token(token_str)

            if outcome is RefreshRotateOutcome.INVALID:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            if outcome is RefreshRotateOutcome.REUSE:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)

            assert rt is not None
            if rt.client_id != client.client_id:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)

            effective_scope = rt.scope
            requested_scope = form.get("scope", "").strip()
            if requested_scope:
                requested_set = set(requested_scope.split())
                stored_set = set(rt.scope.split())
                if not requested_set.issubset(stored_set):
                    return JSONResponse({"error": "invalid_scope"}, status_code=400)
                effective_scope = requested_scope

            user = await self.users.get_by_sub(rt.sub)
            if user is None:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)

            new_access_token = secrets.token_urlsafe(32)
            await self._grants.save_access_token(
                new_access_token, user.sub, int(time.time()) + self._token_ttl, effective_scope
            )
            new_rt = RefreshToken(
                token=secrets.token_urlsafe(32),
                sub=user.sub,
                client_id=client.client_id,
                scope=effective_scope,
                family_id=rt.family_id,
                expires_at=int(time.time()) + self._refresh_token_ttl,
            )
            await self._grants.save_refresh_token(new_rt)

            return JSONResponse(
                {
                    "access_token": new_access_token,
                    "token_type": "Bearer",
                    "expires_in": self._token_ttl,
                    "scope": effective_scope,
                    "refresh_token": new_rt.token,
                    "id_token": self._make_refresh_id_token(rt, user),
                }
            )

        @router.get("/userinfo")
        async def userinfo(request: Request) -> Response:
            header = request.headers.get("authorization", "")
            token_value = header[7:].strip() if header.lower().startswith("bearer ") else ""
            entry = await self._grants.get_access_token(token_value)
            if entry is None:
                return JSONResponse({"error": "invalid_token"}, status_code=401)
            sub, _exp, scope = entry
            user = await self.users.get_by_sub(sub)
            if user is None:
                return JSONResponse({"error": "invalid_token"}, status_code=401)
            filtered = _filter_claims_by_scope(user.claims, scope)
            return JSONResponse({"sub": user.sub, **filtered})

        return router

    async def _auto_login_user(self) -> IdpUser | None:
        if self.auto_login is None:
            return None
        return await self.users.get_by_username(self.auto_login)
