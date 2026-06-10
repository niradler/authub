from __future__ import annotations

import pytest
from pydantic import AnyHttpUrl, SecretStr, TypeAdapter

from authub.errors import IdentityProviderNotFoundError
from authub.models import CanonicalIdentity, IdentityProvider, OidcSettings, PrincipalType
from authub.stores.memory import InMemoryIdentityProviderStore, InMemoryUserStore

_url = TypeAdapter(AnyHttpUrl)


def make_conn(conn_id: str = "acme-google", tenant: str = "acme") -> IdentityProvider:
    return IdentityProvider(
        id=conn_id,
        tenant_id=tenant,
        display_name="Google",
        settings=OidcSettings(
            issuer=_url.validate_python("https://accounts.google.com"),
            client_id="c",
            client_secret=SecretStr("s"),
        ),
    )


async def test_connection_get_and_missing() -> None:
    store = InMemoryIdentityProviderStore([make_conn()])
    conn = await store.get("acme-google")
    assert conn.tenant_id == "acme"
    with pytest.raises(IdentityProviderNotFoundError):
        await store.get("nope")


async def test_discovery_by_email_domain() -> None:
    store = InMemoryIdentityProviderStore(
        [make_conn(), make_conn("acme-okta")], domains={"acme.com": "acme"}
    )
    infos = await store.list_for_email("Ada@ACME.com")
    assert {i.idp_id for i in infos} == {"acme-google", "acme-okta"}
    assert infos[0].kind == "oidc"
    assert await store.list_for_email("who@unknown.io") == []


async def test_user_upsert_is_stable_and_updates() -> None:
    store = InMemoryUserStore()
    identity = CanonicalIdentity(external_id="sub-1", email="a@b.co", name="Ada", raw={})
    first = await store.upsert_from_identity(identity, "acme")
    assert first.type is PrincipalType.USER and first.id.startswith("usr_")

    updated = CanonicalIdentity(
        external_id="sub-1", email="new@b.co", name="Ada L", roles=["admin"], raw={}
    )
    second = await store.upsert_from_identity(updated, "acme")
    assert second.id == first.id
    assert second.email == "new@b.co" and second.roles == ["admin"]


async def test_user_roles_kept_when_identity_has_none() -> None:
    store = InMemoryUserStore()
    await store.upsert_from_identity(
        CanonicalIdentity(external_id="s", roles=["admin"], raw={}), "t"
    )
    second = await store.upsert_from_identity(CanonicalIdentity(external_id="s", raw={}), "t")
    assert second.roles == ["admin"]


async def test_users_keyed_by_tenant_and_external_id() -> None:
    store = InMemoryUserStore()
    a = await store.upsert_from_identity(CanonicalIdentity(external_id="s", raw={}), "t1")
    b = await store.upsert_from_identity(CanonicalIdentity(external_id="s", raw={}), "t2")
    assert a.id != b.id
    assert await store.get("t1", "s") is not None
    assert await store.get("t1", "missing") is None
