from __future__ import annotations

from typing import Any

import pytest

from authub.errors import ForbiddenError
from authub.models import CanonicalIdentity, Principal, PrincipalType, TokenClaims
from authub.plugins import Plugin, PluginChain


def make_principal() -> Principal:
    return Principal(id="u1", type=PrincipalType.USER, tenant_id="t")


def make_identity() -> CanonicalIdentity:
    return CanonicalIdentity(external_id="x", raw={})


async def test_before_issue_token_chains_in_order() -> None:
    class A(Plugin):
        async def before_issue_token(
            self,
            claims: dict[str, Any],
            principal: Principal,
            identity: CanonicalIdentity | None,
        ) -> dict[str, Any]:
            return {**claims, "a": 1}

    class B(Plugin):
        async def before_issue_token(
            self,
            claims: dict[str, Any],
            principal: Principal,
            identity: CanonicalIdentity | None,
        ) -> dict[str, Any]:
            assert claims["a"] == 1
            return {**claims, "b": 2}

    chain = PluginChain([A(), B()])
    out = await chain.before_issue_token({"sub": "u1"}, make_principal(), make_identity())
    assert out == {"sub": "u1", "a": 1, "b": 2}


async def test_on_token_verify_can_reject() -> None:
    class Deny(Plugin):
        async def on_token_verify(self, claims: TokenClaims) -> None:
            raise ForbiddenError("step-up required")

    chain = PluginChain([Plugin(), Deny()])
    claims = TokenClaims(
        sub="u1", token_type=PrincipalType.USER, tenant_id="t", jti="j", iat=0, claims={}
    )
    with pytest.raises(ForbiddenError):
        await chain.on_token_verify(claims)


async def test_defaults_are_noops() -> None:
    chain = PluginChain([Plugin()])
    out = await chain.before_issue_token({"k": "v"}, make_principal(), None)
    assert out == {"k": "v"}
