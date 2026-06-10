from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
import time
import uuid
from abc import ABC, abstractmethod
from typing import Any

from authub.idp.models import AuthCode, IdpUser

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1


def hash_password(password: str) -> str:
    """Hash a password using scrypt. Returns a storable string."""
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its stored hash. Constant-time compare."""
    try:
        scheme, salt_hex, digest_hex = password_hash.split("$")
        if scheme != "scrypt":
            return False
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.scrypt(
            password.encode(),
            salt=bytes.fromhex(salt_hex),
            n=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(expected, actual)


class IdpGrantStore(ABC):
    """Store for authorization codes and access tokens.

    Implementations must be safe for concurrent async access.
    consume_code must be atomic: each code can be redeemed at most once.
    All retrieval methods must return None for expired entries.
    """

    @abstractmethod
    async def save_code(self, code: AuthCode) -> None:
        """Persist an authorization code."""
        ...

    @abstractmethod
    async def consume_code(self, code: str) -> AuthCode | None:
        """Atomically pop and return the code, or None if missing or expired."""
        ...

    @abstractmethod
    async def save_access_token(self, token: str, sub: str, expires_at: int) -> None:
        """Persist an access token with its subject and expiry epoch."""
        ...

    @abstractmethod
    async def get_access_token(self, token: str) -> tuple[str, int] | None:
        """Return (sub, expires_at) for a non-expired token, or None."""
        ...


class InMemoryIdpGrantStore(IdpGrantStore):
    """In-process grant store. Not suitable for multi-instance deployments."""

    def __init__(self) -> None:
        self._codes: dict[str, AuthCode] = {}
        self._access_tokens: dict[str, tuple[str, int]] = {}

    async def save_code(self, code: AuthCode) -> None:
        self._evict_expired_codes()
        self._codes[code.code] = code

    async def consume_code(self, code: str) -> AuthCode | None:
        entry = self._codes.pop(code, None)
        if entry is None or entry.expires_at <= int(time.time()):
            return None
        return entry

    async def save_access_token(self, token: str, sub: str, expires_at: int) -> None:
        self._evict_expired_tokens()
        self._access_tokens[token] = (sub, expires_at)

    async def get_access_token(self, token: str) -> tuple[str, int] | None:
        entry = self._access_tokens.get(token)
        if entry is None or entry[1] <= int(time.time()):
            return None
        return entry

    def _evict_expired_codes(self) -> None:
        now = int(time.time())
        expired = [k for k, v in self._codes.items() if v.expires_at <= now]
        for k in expired:
            del self._codes[k]

    def _evict_expired_tokens(self) -> None:
        now = int(time.time())
        expired = [k for k, v in self._access_tokens.items() if v[1] <= now]
        for k in expired:
            del self._access_tokens[k]


class IdpUserStore(ABC):
    """Abstract user store for AuthubIdp."""

    @abstractmethod
    async def authenticate(self, username: str, password: str) -> IdpUser | None:
        """Return the user if credentials are valid, else None."""
        ...

    @abstractmethod
    async def get_by_sub(self, sub: str) -> IdpUser | None:
        """Return the user with the given sub, or None."""
        ...

    @abstractmethod
    async def get_by_username(self, username: str) -> IdpUser | None:
        """Return the user with the given username, or None."""
        ...


class InMemoryIdpUserStore(IdpUserStore):
    """In-process user store. Not suitable for multi-instance deployments."""

    def __init__(self) -> None:
        self._by_username: dict[str, IdpUser] = {}
        self._by_sub: dict[str, IdpUser] = {}

    def add_user(
        self,
        username: str,
        password: str,
        *,
        sub: str | None = None,
        email: str | None = None,
        name: str | None = None,
        extra_claims: dict[str, Any] | None = None,
    ) -> IdpUser:
        """Add a user to the store. Hashes the password synchronously (setup-time only)."""
        claims: dict[str, Any] = dict(extra_claims or {})
        if email is not None:
            claims["email"] = email
        if name is not None:
            claims["name"] = name
        user = IdpUser(
            username=username,
            password_hash=hash_password(password),
            sub=sub if sub is not None else f"authub|{uuid.uuid4().hex[:12]}",
            claims=claims,
        )
        self._by_username[username] = user
        self._by_sub[user.sub] = user
        return user

    async def authenticate(self, username: str, password: str) -> IdpUser | None:
        """Verify credentials. Runs scrypt off the event loop."""
        user = self._by_username.get(username)
        if user is None:
            return None
        ok = await asyncio.to_thread(verify_password, password, user.password_hash)
        if not ok:
            return None
        return user

    async def get_by_sub(self, sub: str) -> IdpUser | None:
        return self._by_sub.get(sub)

    async def get_by_username(self, username: str) -> IdpUser | None:
        return self._by_username.get(username)
