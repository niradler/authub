from __future__ import annotations

from abc import ABC, abstractmethod

from authub.models import CanonicalIdentity, Connection, ConnectionInfo, Principal


class ConnectionStore(ABC):
    """Abstract store for ``Connection`` configuration objects."""

    @abstractmethod
    async def get(self, connection_id: str) -> Connection:
        """Return the connection by ID. Raise ``ConnectionNotFoundError`` when absent."""
        ...

    @abstractmethod
    async def list_for_tenant(self, tenant_id: str) -> list[Connection]:
        """Return all connections belonging to a tenant."""
        ...

    @abstractmethod
    async def list_for_email(self, email: str) -> list[ConnectionInfo]:
        """Return public ``ConnectionInfo`` records matched by the email's domain."""
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
