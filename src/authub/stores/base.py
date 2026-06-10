from __future__ import annotations

from abc import ABC, abstractmethod

from authub.models import CanonicalIdentity, IdentityProvider, IdentityProviderInfo, Principal


class IdentityProviderStore(ABC):
    """Abstract store for ``IdentityProvider`` configuration objects."""

    @abstractmethod
    async def get(self, idp_id: str) -> IdentityProvider:
        """Return the identity provider by ID. Raise ``IdentityProviderNotFoundError`` if absent."""
        ...

    @abstractmethod
    async def list_for_tenant(self, tenant_id: str) -> list[IdentityProvider]:
        """Return all identity providers belonging to a tenant."""
        ...

    @abstractmethod
    async def list_for_email(self, email: str) -> list[IdentityProviderInfo]:
        """Return public ``IdentityProviderInfo`` records matched by the email's domain."""
        ...


class UserStore(ABC):
    """Abstract store for user ``Principal`` records."""

    @abstractmethod
    async def get(self, tenant_id: str, external_id: str) -> Principal | None:
        """Return the principal for a (tenant, IdP subject) pair, or ``None`` if not found."""
        ...

    @abstractmethod
    async def upsert_from_identity(self, identity: CanonicalIdentity, tenant_id: str) -> Principal:
        """Create or update a principal from a canonical identity and return it."""
        ...
