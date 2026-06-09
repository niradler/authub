from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from abc import ABC, abstractmethod
from typing import Any

from authub.idp.models import IdpUser

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
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


class IdpUserStore(ABC):
    @abstractmethod
    async def authenticate(self, username: str, password: str) -> IdpUser | None: ...

    @abstractmethod
    async def get_by_sub(self, sub: str) -> IdpUser | None: ...

    @abstractmethod
    async def get_by_username(self, username: str) -> IdpUser | None: ...


class InMemoryIdpUserStore(IdpUserStore):
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
        claims: dict[str, Any] = dict(extra_claims or {})
        if email is not None:
            claims["email"] = email
        if name is not None:
            claims["name"] = name
        user = IdpUser(
            username=username,
            password_hash=hash_password(password),
            sub=sub if sub is not None else f"dev|{uuid.uuid4().hex[:12]}",
            claims=claims,
        )
        self._by_username[username] = user
        self._by_sub[user.sub] = user
        return user

    async def authenticate(self, username: str, password: str) -> IdpUser | None:
        user = self._by_username.get(username)
        if user is None or not verify_password(password, user.password_hash):
            return None
        return user

    async def get_by_sub(self, sub: str) -> IdpUser | None:
        return self._by_sub.get(sub)

    async def get_by_username(self, username: str) -> IdpUser | None:
        return self._by_username.get(username)
