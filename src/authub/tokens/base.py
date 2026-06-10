from __future__ import annotations

import heapq
import time
from abc import ABC, abstractmethod
from typing import Any

from authub.models import TokenClaims


class TokenService(ABC):
    """Abstract interface for signing and verifying authub JWTs."""

    @abstractmethod
    async def sign(self, claims: dict[str, Any]) -> str:
        """Sign a claims dict and return a compact JWT string."""
        ...

    @abstractmethod
    async def verify(self, token: str) -> TokenClaims:
        """Verify a JWT and return typed claims. Raise ``InvalidTokenError`` on failure."""
        ...


class RevocationStore(ABC):
    """Abstract store for tracking revoked JWT IDs."""

    @abstractmethod
    async def is_revoked(self, jti: str) -> bool:
        """Return ``True`` if the given JTI has been revoked."""
        ...

    @abstractmethod
    async def revoke(self, jti: str, exp: int | None) -> None:
        """Mark a JTI as revoked until its expiry epoch. Pass ``None`` for non-expiring entries."""
        ...


class InMemoryRevocationStore(RevocationStore):
    """In-process revocation store backed by a dict and a min-heap for O(log n) expiry eviction.

    Not suitable for multi-process deployments — each process maintains its own state.
    """

    def __init__(self) -> None:
        self._store: dict[str, int | None] = {}
        self._heap: list[tuple[int, str]] = []

    def _evict_expired(self) -> None:
        now = int(time.time())
        while self._heap and self._heap[0][0] <= now:
            _exp, jti = heapq.heappop(self._heap)
            stored = self._store.get(jti)
            if stored is not None and stored <= now:
                del self._store[jti]

    async def is_revoked(self, jti: str) -> bool:
        """Evict stale entries, then return ``True`` if the JTI is present."""
        self._evict_expired()
        return jti in self._store

    async def revoke(self, jti: str, exp: int | None) -> None:
        """Add the JTI to the revocation set. Ignores already-expired tokens."""
        if exp is not None and exp <= int(time.time()):
            return
        self._store[jti] = exp
        if exp is not None:
            heapq.heappush(self._heap, (exp, jti))
