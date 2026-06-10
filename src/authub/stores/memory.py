from __future__ import annotations

from collections.abc import Iterable
from uuid import uuid4

from authub.errors import IdentityProviderNotFoundError
from authub.models import (
    CanonicalIdentity,
    IdentityProvider,
    IdentityProviderInfo,
    Principal,
    PrincipalType,
)
from authub.stores.base import IdentityProviderStore, UserStore


class InMemoryIdentityProviderStore(IdentityProviderStore):
    """In-process identity provider store. Suitable for tests and single-process deployments.

    Args:
        identity_providers: Initial ``IdentityProvider`` objects to register.
        domains: Mapping of email domain (lower-cased) to ``tenant_id`` for discovery lookups.
    """

    def __init__(
        self,
        identity_providers: Iterable[IdentityProvider] = (),
        domains: dict[str, str] | None = None,
    ) -> None:
        self._by_id: dict[str, IdentityProvider] = {}
        self._domains: dict[str, str] = {k.lower(): v for k, v in (domains or {}).items()}
        for idp in identity_providers:
            self._by_id[idp.id] = idp

    def add(self, identity_provider: IdentityProvider) -> None:
        """Register or replace an identity provider at runtime."""
        self._by_id[identity_provider.id] = identity_provider

    async def get(self, idp_id: str) -> IdentityProvider:
        idp = self._by_id.get(idp_id)
        if idp is None:
            raise IdentityProviderNotFoundError()
        return idp

    async def list_for_tenant(self, tenant_id: str) -> list[IdentityProvider]:
        return [c for c in self._by_id.values() if c.tenant_id == tenant_id]

    async def list_for_email(self, email: str) -> list[IdentityProviderInfo]:
        domain = email.lower().split("@", 1)[-1]
        tenant_id = self._domains.get(domain)
        if tenant_id is None:
            return []
        return [
            IdentityProviderInfo(
                idp_id=c.id,
                display_name=c.display_name,
                kind=c.settings.kind,
            )
            for c in self._by_id.values()
            if c.tenant_id == tenant_id
        ]


class InMemoryUserStore(UserStore):
    """In-process user store keyed by ``(tenant_id, external_id)``.

    On upsert, email and name are updated from the latest identity; roles are refreshed when
    non-empty.
    """

    def __init__(self) -> None:
        self._users: dict[tuple[str, str], Principal] = {}

    async def get(self, tenant_id: str, external_id: str) -> Principal | None:
        return self._users.get((tenant_id, external_id))

    async def upsert_from_identity(self, identity: CanonicalIdentity, tenant_id: str) -> Principal:
        key = (tenant_id, identity.external_id)
        existing = self._users.get(key)
        if existing is None:
            principal = Principal(
                id=f"usr_{uuid4().hex[:16]}",
                type=PrincipalType.USER,
                tenant_id=tenant_id,
                email=identity.email,
                name=identity.name,
                roles=list(identity.roles),
            )
            self._users[key] = principal
            return principal

        updated = existing.model_copy(
            update={
                "email": identity.email if identity.email is not None else existing.email,
                "name": identity.name if identity.name is not None else existing.name,
                "roles": list(identity.roles) if identity.roles else existing.roles,
            }
        )
        self._users[key] = updated
        return updated
