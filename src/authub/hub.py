from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import timedelta
from functools import cached_property

from fastapi import APIRouter, FastAPI
from pydantic import SecretStr

from authub.email.base import EmailSender
from authub.email.console import ConsoleEmailSender
from authub.errors import AuthubError, ForbiddenError, TokenRevokedError
from authub.flow import AuthFlow
from authub.mapping import Mapper
from authub.models import Principal, PrincipalType, SessionCookieConfig, TokenClaims
from authub.plugins import Plugin, PluginChain
from authub.protocols.base import HttpOptions, ProtocolRegistry
from authub.protocols.oauth2 import OAuth2Protocol
from authub.protocols.oidc import OidcProtocol
from authub.state import FlowStateCodec
from authub.stores.base import ConnectionStore, UserStore
from authub.stores.memory import InMemoryUserStore
from authub.tokens.base import RevocationStore, TokenService
from authub.tokens.claims import build_service_claims
from authub.web.deps import (
    PrincipalDependency,
    make_principal_dependency,
    make_roles_dependency,
    make_scopes_dependency,
)
from authub.web.router import authub_error_handler, build_router

logger = logging.getLogger(__name__)


class Authub:
    """Central configuration object for authub.

    Wire it once, then call ``attach`` or use the ``router`` property.

    Args:
        connections: Store of ``Connection`` records (required).
        tokens: JWT signing/verification service (required).
        state_secret: Symmetric secret for login-flow state cookies; at least 32 characters.
        users: User store; defaults to ``InMemoryUserStore`` when omitted.
        email: Email sender; defaults to ``ConsoleEmailSender`` when omitted.
        revocation: Optional revocation store; revocation is skipped when ``None``.
        plugins: Ordered plugin hooks applied to every login and token operation.
        mapper: Custom claim mapper; defaults to ``Mapper()`` when omitted.
        user_token_ttl: Lifetime for user JWTs (default 8 hours).
        session_cookie: Enable browser-session cookies and CSRF protection when provided.
        public_base_url: Override the base URL used to build callback URLs (useful behind a proxy).
    """

    def __init__(
        self,
        *,
        connections: ConnectionStore,
        tokens: TokenService,
        state_secret: str | SecretStr,
        users: UserStore | None = None,
        email: EmailSender | None = None,
        revocation: RevocationStore | None = None,
        plugins: Sequence[Plugin] = (),
        mapper: Mapper | None = None,
        user_token_ttl: timedelta = timedelta(hours=8),
        session_cookie: SessionCookieConfig | None = None,
        public_base_url: str | None = None,
    ) -> None:
        self.connections = connections
        self.tokens = tokens
        self.users = users if users is not None else InMemoryUserStore()
        self.email = email if email is not None else ConsoleEmailSender()
        self.revocation = revocation
        self.plugins = PluginChain(plugins)
        self.session_cookie = session_cookie
        self.public_base_url = public_base_url.rstrip("/") if public_base_url is not None else None
        self.user_token_ttl = user_token_ttl
        self.state_codec = FlowStateCodec(secret=state_secret)

        self.http = HttpOptions()
        self.registry = ProtocolRegistry()
        self.registry.register(OidcProtocol(self.http))
        self.registry.register(OAuth2Protocol(self.http))
        self._register_saml()

        self.flow = AuthFlow(
            connections=self.connections,
            users=self.users,
            tokens=self.tokens,
            registry=self.registry,
            plugins=self.plugins,
            mapper=mapper if mapper is not None else Mapper(),
            user_token_ttl=user_token_ttl,
        )

    def _register_saml(self) -> None:
        try:
            from authub.protocols.saml import SamlProtocol  # noqa: PLC0415
        except Exception:
            logger.debug("pysaml2 unavailable; SAML protocol not registered")
            return
        self.registry.register(SamlProtocol())

    async def verify_token(self, token: str) -> TokenClaims:
        """Verify a JWT and run plugin hooks.

        Raise ``InvalidTokenError`` or ``TokenRevokedError`` on failure.
        """
        claims = await self.tokens.verify(token)
        if self.revocation is not None and await self.revocation.is_revoked(claims.jti):
            raise TokenRevokedError()
        await self.plugins.on_token_verify(claims)
        return claims

    async def issue_service_token(
        self, principal: Principal, *, ttl: timedelta | None = None
    ) -> str:
        """Sign a service JWT for a ``SERVICE`` principal.

        Raise ``ForbiddenError`` for user principals. Pass ``ttl=None`` for a non-expiring token.
        """
        if principal.type is not PrincipalType.SERVICE:
            raise ForbiddenError("issue_service_token requires a service principal")
        claims = build_service_claims(principal, ttl)
        claims = await self.plugins.before_issue_token(claims, principal, None)
        return await self.tokens.sign(claims)

    @property
    def current_user(self) -> PrincipalDependency:
        """FastAPI dependency that requires a valid user JWT and returns the ``Principal``."""
        return make_principal_dependency(self, PrincipalType.USER)

    @property
    def current_principal(self) -> PrincipalDependency:
        """FastAPI dependency that accepts any valid JWT (user or service).

        Returns the resolved ``Principal``.
        """
        return make_principal_dependency(self)

    def require_scopes(self, *scopes: str) -> PrincipalDependency:
        """FastAPI dependency that requires the principal to hold ALL of the given scopes."""
        return make_scopes_dependency(self, scopes)

    def require_roles(self, *roles: str) -> PrincipalDependency:
        """FastAPI dependency that requires the principal to hold ANY of the given roles."""
        return make_roles_dependency(self, roles)

    @cached_property
    def router(self) -> APIRouter:
        """Lazily built ``APIRouter`` with login, callback, logout, and discover routes."""
        return build_router(self)

    def attach(self, app: FastAPI, prefix: str = "/auth") -> None:
        """Mount the authub router and error handler onto a FastAPI application.

        Args:
            app: The FastAPI application to mount onto.
            prefix: URL prefix for all authub routes (default ``"/auth"``).
        """
        app.include_router(self.router, prefix=prefix)
        app.add_exception_handler(AuthubError, authub_error_handler)
