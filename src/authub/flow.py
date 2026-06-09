from __future__ import annotations

from datetime import timedelta

from starlette.requests import Request

from authub.mapping import Mapper
from authub.models import Principal
from authub.plugins import PluginChain
from authub.protocols.base import ProtocolRegistry
from authub.state import BeginResult, FlowState
from authub.stores.base import ConnectionStore, UserStore
from authub.tokens.base import TokenService
from authub.tokens.claims import build_user_claims


class AuthFlow:
    def __init__(
        self,
        *,
        connections: ConnectionStore,
        users: UserStore,
        tokens: TokenService,
        registry: ProtocolRegistry,
        plugins: PluginChain,
        mapper: Mapper,
        user_token_ttl: timedelta,
    ) -> None:
        self.connections = connections
        self.users = users
        self.tokens = tokens
        self.registry = registry
        self.plugins = plugins
        self.mapper = mapper
        self.user_token_ttl = user_token_ttl

    async def begin(self, *, connection_id: str, callback_url: str, return_to: str) -> BeginResult:
        conn = await self.connections.get(connection_id)
        protocol = self.registry.get(conn.settings.kind)
        return await protocol.begin(conn=conn, callback_url=callback_url, return_to=return_to)

    async def complete(
        self,
        *,
        request: Request,
        connection_id: str,
        callback_url: str,
        flow_state: FlowState,
    ) -> tuple[str, Principal]:
        conn = await self.connections.get(connection_id)
        protocol = self.registry.get(conn.settings.kind)
        raw = await protocol.complete(
            request=request, conn=conn, callback_url=callback_url, flow_state=flow_state
        )
        await self.plugins.on_identity(raw, conn)
        identity = self.mapper.normalize(raw, conn.mapping)
        principal = await self.users.upsert_from_identity(identity, conn.tenant_id)
        await self.plugins.on_user_provisioned(principal, identity)
        claims = build_user_claims(principal, identity, self.user_token_ttl)
        claims = await self.plugins.before_issue_token(claims, principal, identity)
        token = await self.tokens.sign(claims)
        return token, principal
