from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from authub.models import (
        CanonicalIdentity,
        IdentityProvider,
        Principal,
        RawIdentity,
        TokenClaims,
    )


class Plugin:
    """Base class for authub plugins. Override any hook; unoverridden hooks are no-ops.

    Raising any exception from a hook propagates to the caller and aborts the current operation.
    """

    async def on_identity(self, raw: RawIdentity, idp: IdentityProvider) -> None:
        """Called after the IdP callback is parsed but before claim mapping.

        Use to inspect or reject raw IdP claims. Raise to block the login.
        """

    async def on_user_provisioned(self, principal: Principal, identity: CanonicalIdentity) -> None:
        """Called after a user is created or updated in the ``UserStore``.

        Use to sync the principal to an external directory. Raise to abort token issuance.
        """

    async def before_issue_token(
        self,
        claims: dict[str, Any],
        principal: Principal,
        identity: CanonicalIdentity | None,
    ) -> dict[str, Any]:
        """Called immediately before a JWT is signed. Return the (possibly mutated) claims dict.

        Use to inject or redact JWT claims. ``identity`` is ``None`` for service tokens.
        Raise to block token issuance.
        """
        return claims

    async def on_token_verify(self, claims: TokenClaims) -> None:
        """Called after a JWT passes signature and claims validation on every request.

        Use to enforce additional constraints (e.g. tenant allow-lists). Raise to reject the token.
        """


class PluginChain:
    """Fan-out runner that calls each registered ``Plugin`` in order."""

    def __init__(self, plugins: Sequence[Plugin] = ()) -> None:
        self._plugins = list(plugins)

    async def on_identity(self, raw: RawIdentity, idp: IdentityProvider) -> None:
        """Invoke ``on_identity`` on each plugin in registration order."""
        for plugin in self._plugins:
            await plugin.on_identity(raw, idp)

    async def on_user_provisioned(self, principal: Principal, identity: CanonicalIdentity) -> None:
        """Invoke ``on_user_provisioned`` on each plugin in registration order."""
        for plugin in self._plugins:
            await plugin.on_user_provisioned(principal, identity)

    async def before_issue_token(
        self,
        claims: dict[str, Any],
        principal: Principal,
        identity: CanonicalIdentity | None,
    ) -> dict[str, Any]:
        """Pass claims through each plugin's ``before_issue_token``, threading the result."""
        result = claims
        for plugin in self._plugins:
            result = await plugin.before_issue_token(result, principal, identity)
        return result

    async def on_token_verify(self, claims: TokenClaims) -> None:
        """Invoke ``on_token_verify`` on each plugin in registration order."""
        for plugin in self._plugins:
            await plugin.on_token_verify(claims)
