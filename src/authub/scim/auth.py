from __future__ import annotations

import secrets
from abc import ABC, abstractmethod


class ScimAuthenticator(ABC):
    """Resolve a bearer token to a tenant_id, or return None if invalid."""

    @abstractmethod
    async def resolve(self, token: str) -> str | None:
        """Return the tenant_id for the given bearer token, or None if unrecognized."""
        ...


class StaticTokenAuthenticator(ScimAuthenticator):
    """Authenticate via a static mapping of bearer token -> tenant_id.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        tokens: Mapping of bearer token string to tenant_id.
    """

    def __init__(self, tokens: dict[str, str]) -> None:
        self._tokens = tokens

    async def resolve(self, token: str) -> str | None:
        for candidate, tenant_id in self._tokens.items():
            if secrets.compare_digest(candidate, token):
                return tenant_id
        return None
