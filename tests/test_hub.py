from __future__ import annotations

from datetime import timedelta

import pytest

from authub.errors import ForbiddenError, TokenRevokedError
from authub.hub import Authub
from authub.models import Principal, PrincipalType
from authub.stores.memory import InMemoryConnectionStore
from authub.tokens.base import InMemoryRevocationStore
from authub.tokens.jwt import JwtTokenService

SECRET = "s" * 32


def make_hub(**kwargs: object) -> Authub:
    return Authub(
        connections=InMemoryConnectionStore(),
        tokens=JwtTokenService.hs256(SECRET),
        state_secret="x" * 32,
        **kwargs,  # type: ignore[arg-type]
    )


def test_builtin_protocols_registered() -> None:
    hub = make_hub()
    assert hub.registry.get("oidc").kind == "oidc"
    assert hub.registry.get("oauth2").kind == "oauth2"


async def test_issue_and_verify_service_token() -> None:
    hub = make_hub()
    svc = Principal(
        id="svc_ci", type=PrincipalType.SERVICE, tenant_id="acme", scopes=["builds:write"]
    )
    token = await hub.issue_service_token(svc)
    claims = await hub.verify_token(token)
    assert claims.token_type is PrincipalType.SERVICE
    assert claims.scopes == ["builds:write"]
    assert claims.exp is None


async def test_issue_service_token_rejects_user_principal() -> None:
    hub = make_hub()
    user = Principal(id="u1", type=PrincipalType.USER, tenant_id="t")
    with pytest.raises(ForbiddenError):
        await hub.issue_service_token(user)


async def test_service_token_with_ttl_has_exp() -> None:
    hub = make_hub()
    svc = Principal(id="svc", type=PrincipalType.SERVICE, tenant_id="t")
    token = await hub.issue_service_token(svc, ttl=timedelta(minutes=5))
    claims = await hub.verify_token(token)
    assert claims.exp is not None


async def test_revocation_enforced_on_verify() -> None:
    hub = make_hub(revocation=InMemoryRevocationStore())
    svc = Principal(id="svc", type=PrincipalType.SERVICE, tenant_id="t")
    token = await hub.issue_service_token(svc)
    claims = await hub.verify_token(token)
    await hub.revocation.revoke(claims.jti, claims.exp)  # type: ignore[union-attr]
    with pytest.raises(TokenRevokedError):
        await hub.verify_token(token)
