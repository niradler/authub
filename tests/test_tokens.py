from __future__ import annotations

import time
from datetime import timedelta

import pytest

from authub.errors import ConfigurationError, InvalidTokenError
from authub.models import CanonicalIdentity, Principal, PrincipalType
from authub.tokens.base import InMemoryRevocationStore
from authub.tokens.claims import build_service_claims, build_user_claims
from authub.tokens.jwt import JwtTokenService

SECRET = "s" * 32


def user_principal() -> Principal:
    return Principal(
        id="usr_1",
        type=PrincipalType.USER,
        tenant_id="acme",
        email="a@b.co",
        name="Ada",
        roles=["admin"],
    )


def test_build_user_claims_shape() -> None:
    claims = build_user_claims(
        user_principal(), CanonicalIdentity(external_id="x", raw={}), timedelta(hours=1)
    )
    assert claims["sub"] == "usr_1"
    assert claims["token_type"] == "user"
    assert claims["tid"] == "acme"
    assert claims["roles"] == ["admin"]
    assert claims["exp"] - claims["iat"] == 3600
    assert len(claims["jti"]) >= 16


def test_build_service_claims_no_exp_by_default() -> None:
    svc = Principal(id="svc_ci", type=PrincipalType.SERVICE, tenant_id="acme", scopes=["b:w"])
    claims = build_service_claims(svc, ttl=None)
    assert "exp" not in claims
    assert claims["scopes"] == ["b:w"]
    assert claims["token_type"] == "service"


async def test_hs256_roundtrip() -> None:
    svc = JwtTokenService.hs256(SECRET)
    token = await svc.sign(
        build_user_claims(
            user_principal(), CanonicalIdentity(external_id="x", raw={}), timedelta(hours=1)
        )
    )
    claims = await svc.verify(token)
    assert claims.sub == "usr_1"
    assert claims.tenant_id == "acme"
    assert claims.token_type is PrincipalType.USER
    assert claims.email == "a@b.co"


async def test_ed25519_roundtrip_and_verify_only_service() -> None:
    svc = JwtTokenService.ed25519()
    token = await svc.sign(
        build_user_claims(
            user_principal(), CanonicalIdentity(external_id="x", raw={}), timedelta(hours=1)
        )
    )
    verifier = JwtTokenService.ed25519_verifier(svc.public_key_pem)
    claims = await verifier.verify(token)
    assert claims.sub == "usr_1"


async def test_expired_token_rejected() -> None:
    svc = JwtTokenService.hs256(SECRET, leeway=0)
    claims = build_user_claims(
        user_principal(), CanonicalIdentity(external_id="x", raw={}), timedelta(hours=1)
    )
    claims["exp"] = int(time.time()) - 10
    token = await svc.sign(claims)
    with pytest.raises(InvalidTokenError):
        await svc.verify(token)


async def test_wrong_issuer_rejected() -> None:
    a = JwtTokenService.hs256(SECRET, issuer="a")
    b = JwtTokenService.hs256(SECRET, issuer="b")
    token = await a.sign(
        build_user_claims(
            user_principal(), CanonicalIdentity(external_id="x", raw={}), timedelta(hours=1)
        )
    )
    with pytest.raises(InvalidTokenError):
        await b.verify(token)


async def test_garbage_token_rejected() -> None:
    svc = JwtTokenService.hs256(SECRET)
    with pytest.raises(InvalidTokenError):
        await svc.verify("not.a.jwt")


async def test_user_token_without_exp_rejected() -> None:
    svc = JwtTokenService.hs256(SECRET)
    claims = build_user_claims(
        user_principal(), CanonicalIdentity(external_id="x", raw={}), timedelta(hours=1)
    )
    del claims["exp"]
    token = await svc.sign(claims)
    with pytest.raises(InvalidTokenError):
        await svc.verify(token)


def test_short_hs256_secret_rejected() -> None:
    with pytest.raises(ConfigurationError):
        JwtTokenService.hs256("short")


async def test_revocation_store() -> None:
    store = InMemoryRevocationStore()
    assert not await store.is_revoked("j1")
    await store.revoke("j1", exp=int(time.time()) + 60)
    assert await store.is_revoked("j1")
    await store.revoke("j2", exp=int(time.time()) - 1)
    assert not await store.is_revoked("j2")


async def test_revocation_store_none_exp_never_expires() -> None:
    store = InMemoryRevocationStore()
    await store.revoke("eternal", exp=None)
    assert await store.is_revoked("eternal")
    store._evict_expired()
    assert await store.is_revoked("eternal")


async def test_revocation_store_expired_entries_evicted_on_lookup() -> None:
    store = InMemoryRevocationStore()
    await store.revoke("soon", exp=int(time.time()) + 60)
    await store.revoke("past", exp=int(time.time()) - 1)
    assert await store.is_revoked("soon")
    assert not await store.is_revoked("past")
    assert "past" not in store._store
