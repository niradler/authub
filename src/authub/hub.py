from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import timedelta

from pydantic import SecretStr

from authub.email.base import EmailSender
from authub.email.console import ConsoleEmailSender
from authub.errors import ForbiddenError, TokenRevokedError
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

logger = logging.getLogger(__name__)


class Authub:
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
        except ImportError:
            logger.debug("pysaml2 not installed; SAML protocol not registered")
            return
        self.registry.register(SamlProtocol())

    async def verify_token(self, token: str) -> TokenClaims:
        claims = await self.tokens.verify(token)
        if self.revocation is not None and await self.revocation.is_revoked(claims.jti):
            raise TokenRevokedError()
        await self.plugins.on_token_verify(claims)
        return claims

    async def issue_service_token(
        self, principal: Principal, *, ttl: timedelta | None = None
    ) -> str:
        if principal.type is not PrincipalType.SERVICE:
            raise ForbiddenError("issue_service_token requires a service principal")
        claims = build_service_claims(principal, ttl)
        claims = await self.plugins.before_issue_token(claims, principal, None)
        return await self.tokens.sign(claims)
