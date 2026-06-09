from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

from authub.models import TokenClaims


class TokenService(ABC):
    @abstractmethod
    async def sign(self, claims: dict[str, Any]) -> str: ...

    @abstractmethod
    async def verify(self, token: str) -> TokenClaims: ...


class RevocationStore(ABC):
    @abstractmethod
    async def is_revoked(self, jti: str) -> bool: ...

    @abstractmethod
    async def revoke(self, jti: str, exp: int | None) -> None: ...


class InMemoryRevocationStore(RevocationStore):
    def __init__(self) -> None:
        self._store: dict[str, int | None] = {}

    async def is_revoked(self, jti: str) -> bool:
        now = int(time.time())
        expired = [k for k, exp in self._store.items() if exp is not None and exp <= now]
        for k in expired:
            del self._store[k]
        return jti in self._store

    async def revoke(self, jti: str, exp: int | None) -> None:
        if exp is not None and exp <= int(time.time()):
            return
        self._store[jti] = exp
