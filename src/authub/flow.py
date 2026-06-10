from __future__ import annotations

from datetime import timedelta

from starlette.requests import Request

from authub.mapping import Mapper
from authub.models import Principal
from authub.plugins import PluginChain
from authub.protocols.base import ProtocolRegistry
from authub.state import BeginResult, FlowState
from authub.stores.base import IdentityProviderStore, UserStore
from authub.tokens.base import TokenService
from authub.tokens.claims import build_user_claims


class AuthFlow:
    """Orchestrates the two-step login flow across protocol, store, mapping, and plugin layers."""

    def __init__(
        self,
        *,
        identity_providers: IdentityProviderStore,
        users: UserStore,
        tokens: TokenService,
        registry: ProtocolRegistry,
        plugins: PluginChain,
        mapper: Mapper,
        user_token_ttl: timedelta,
    ) -> None:
        self.identity_providers = identity_providers
        self.users = users
        self.tokens = tokens
        self.registry = registry
        self.plugins = plugins
        self.mapper = mapper
        self.user_token_ttl = user_token_ttl

    async def begin(self, *, idp_id: str, callback_url: str, return_to: str) -> BeginResult:
        """Start a login for the given identity provider. Return the redirect URL and flow state."""
        idp = await self.identity_providers.get(idp_id)
        protocol = self.registry.get(idp.settings.kind)
        return await protocol.begin(idp=idp, callback_url=callback_url, return_to=return_to)

    async def complete(
        self,
        *,
        request: Request,
        idp_id: str,
        callback_url: str,
        flow_state: FlowState,
    ) -> tuple[str, Principal]:
        """Finish a login: validate the callback, map claims, upsert the user, issue a JWT.

        Returns a ``(token, principal)`` tuple. Plugins run at each stage and may raise to abort.
        """
        idp = await self.identity_providers.get(idp_id)
        protocol = self.registry.get(idp.settings.kind)
        raw = await protocol.complete(
            request=request, idp=idp, callback_url=callback_url, flow_state=flow_state
        )
        await self.plugins.on_identity(raw, idp)
        identity = self.mapper.normalize(raw, idp.mapping)
        principal = await self.users.upsert_from_identity(identity, idp.tenant_id)
        await self.plugins.on_user_provisioned(principal, identity)
        claims = build_user_claims(principal, identity, self.user_token_ttl)
        claims = await self.plugins.before_issue_token(claims, principal, identity)
        token = await self.tokens.sign(claims)
        return token, principal
