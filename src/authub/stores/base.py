from __future__ import annotations

from abc import ABC, abstractmethod

from authub.models import CanonicalIdentity, Connection, ConnectionInfo, Principal


class ConnectionStore(ABC):
    @abstractmethod
    async def get(self, connection_id: str) -> Connection: ...

    @abstractmethod
    async def list_for_tenant(self, tenant_id: str) -> list[Connection]: ...

    @abstractmethod
    async def list_for_email(self, email: str) -> list[ConnectionInfo]: ...


class UserStore(ABC):
    @abstractmethod
    async def get(self, tenant_id: str, external_id: str) -> Principal | None: ...

    @abstractmethod
    async def upsert_from_identity(
        self, identity: CanonicalIdentity, tenant_id: str
    ) -> Principal: ...
