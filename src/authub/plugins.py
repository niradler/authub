from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from authub.models import CanonicalIdentity, Connection, Principal, RawIdentity, TokenClaims


class Plugin:
    async def on_identity(self, raw: RawIdentity, conn: Connection) -> None:
        pass

    async def on_user_provisioned(self, principal: Principal, identity: CanonicalIdentity) -> None:
        pass

    async def before_issue_token(
        self,
        claims: dict[str, Any],
        principal: Principal,
        identity: CanonicalIdentity | None,
    ) -> dict[str, Any]:
        return claims

    async def on_token_verify(self, claims: TokenClaims) -> None:
        pass


class PluginChain:
    def __init__(self, plugins: list[Plugin]) -> None:
        self._plugins = plugins

    async def on_identity(self, raw: RawIdentity, conn: Connection) -> None:
        for plugin in self._plugins:
            await plugin.on_identity(raw, conn)

    async def on_user_provisioned(self, principal: Principal, identity: CanonicalIdentity) -> None:
        for plugin in self._plugins:
            await plugin.on_user_provisioned(principal, identity)

    async def before_issue_token(
        self,
        claims: dict[str, Any],
        principal: Principal,
        identity: CanonicalIdentity | None,
    ) -> dict[str, Any]:
        result = claims
        for plugin in self._plugins:
            result = await plugin.before_issue_token(result, principal, identity)
        return result

    async def on_token_verify(self, claims: TokenClaims) -> None:
        for plugin in self._plugins:
            await plugin.on_token_verify(claims)
