from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
import time
import uuid
from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any

from authub.idp.models import AuthCode, IdpUser, RefreshToken

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1


class RefreshRotateOutcome(StrEnum):
    """Result of a rotate/consume operation on a refresh token."""

    ACTIVE = "active"
    REUSE = "reuse"
    INVALID = "invalid"


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
    """Store for authorization codes, access tokens, and refresh tokens.

    Implementations must be safe for concurrent async access.
    consume_code must be atomic: each code can be redeemed at most once.
    All retrieval methods must return None for expired entries.
    rotate_refresh_token must be atomic: ACTIVE marks the token consumed in
    the same operation that returns it; REUSE immediately revokes the family.
    consume_consent_ticket must be atomic: each consent ticket jti is
    accepted at most once regardless of the decision made.
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
    async def save_access_token(self, token: str, sub: str, expires_at: int, scope: str) -> None:
        """Persist an access token with its subject, expiry epoch, and granted scope."""
        ...

    @abstractmethod
    async def get_access_token(self, token: str) -> tuple[str, int, str] | None:
        """Return (sub, expires_at, scope) for a non-expired token, or None."""
        ...

    @abstractmethod
    async def save_refresh_token(self, rt: RefreshToken) -> None:
        """Persist a new refresh token."""
        ...

    @abstractmethod
    async def rotate_refresh_token(
        self, token: str
    ) -> tuple[RefreshRotateOutcome, RefreshToken | None]:
        """Consume a refresh token and return the outcome with its data.

        Returns:
            (ACTIVE, RefreshToken): token was valid and is now consumed (single-use).
            (REUSE, None): token was already consumed; the entire family is revoked.
            (INVALID, None): token unknown, expired, or its family is revoked.
        """
        ...

    @abstractmethod
    async def revoke_refresh_family(self, family_id: str) -> None:
        """Revoke all refresh tokens belonging to a family."""
        ...

    @abstractmethod
    async def consume_consent_ticket(self, jti: str, expires_at: int) -> bool:
        """Atomically record a consent ticket's jti as used.

        Returns True if this jti was not seen before (first use), False if it
        was already consumed. expires_at lets the store evict stale entries.
        """
        ...


class InMemoryIdpGrantStore(IdpGrantStore):
    """In-process grant store. Not suitable for multi-instance deployments."""

    def __init__(self) -> None:
        self._codes: dict[str, AuthCode] = {}
        self._access_tokens: dict[str, tuple[str, int, str]] = {}
        self._refresh_tokens: dict[str, RefreshToken] = {}
        self._consumed_tokens: dict[str, RefreshToken] = {}
        self._revoked_families: set[str] = set()
        self._consumed_consent_tickets: dict[str, int] = {}

    async def save_code(self, code: AuthCode) -> None:
        self._evict_expired_codes()
        self._codes[code.code] = code

    async def consume_code(self, code: str) -> AuthCode | None:
        entry = self._codes.pop(code, None)
        if entry is None or entry.expires_at <= int(time.time()):
            return None
        return entry

    async def save_access_token(self, token: str, sub: str, expires_at: int, scope: str) -> None:
        self._evict_expired_tokens()
        self._access_tokens[token] = (sub, expires_at, scope)

    async def get_access_token(self, token: str) -> tuple[str, int, str] | None:
        entry = self._access_tokens.get(token)
        if entry is None or entry[1] <= int(time.time()):
            return None
        return entry

    async def save_refresh_token(self, rt: RefreshToken) -> None:
        self._evict_expired_refresh_families()
        self._refresh_tokens[rt.token] = rt

    async def rotate_refresh_token(
        self, token: str
    ) -> tuple[RefreshRotateOutcome, RefreshToken | None]:
        now = int(time.time())

        if token in self._consumed_tokens:
            rt = self._consumed_tokens[token]
            await self.revoke_refresh_family(rt.family_id)
            return RefreshRotateOutcome.REUSE, None

        if token not in self._refresh_tokens:
            return RefreshRotateOutcome.INVALID, None
        rt = self._refresh_tokens.pop(token)
        if rt.expires_at <= now or rt.family_id in self._revoked_families:
            return RefreshRotateOutcome.INVALID, None

        self._consumed_tokens[token] = rt
        return RefreshRotateOutcome.ACTIVE, rt

    async def revoke_refresh_family(self, family_id: str) -> None:
        self._revoked_families.add(family_id)
        dead = [t for t, rt in self._refresh_tokens.items() if rt.family_id == family_id]
        for t in dead:
            self._consumed_tokens[t] = self._refresh_tokens.pop(t)

    async def consume_consent_ticket(self, jti: str, expires_at: int) -> bool:
        self._evict_consumed_consent_tickets()
        if jti in self._consumed_consent_tickets:
            return False
        self._consumed_consent_tickets[jti] = expires_at
        return True

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

    def _evict_expired_refresh_families(self) -> None:
        now = int(time.time())
        expired_consumed = [t for t, rt in self._consumed_tokens.items() if rt.expires_at <= now]
        for t in expired_consumed:
            del self._consumed_tokens[t]
        expired_active = [t for t, rt in self._refresh_tokens.items() if rt.expires_at <= now]
        for t in expired_active:
            del self._refresh_tokens[t]

    def _evict_consumed_consent_tickets(self) -> None:
        now = int(time.time())
        expired = [jti for jti, exp in self._consumed_consent_tickets.items() if exp <= now]
        for jti in expired:
            del self._consumed_consent_tickets[jti]


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
