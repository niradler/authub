from __future__ import annotations

from collections.abc import Iterable
from uuid import uuid4

from authub.errors import ConnectionNotFoundError
from authub.models import CanonicalIdentity, Connection, ConnectionInfo, Principal, PrincipalType
from authub.stores.base import ConnectionStore, UserStore


class InMemoryConnectionStore(ConnectionStore):
    """In-process connection store. Suitable for tests and single-process deployments.

    Args:
        connections: Initial ``Connection`` objects to register.
        domains: Mapping of email domain (lower-cased) to ``tenant_id`` for discovery lookups.
    """

    def __init__(
        self,
        connections: Iterable[Connection] = (),
        domains: dict[str, str] | None = None,
    ) -> None:
        self._by_id: dict[str, Connection] = {}
        self._domains: dict[str, str] = {k.lower(): v for k, v in (domains or {}).items()}
        for conn in connections:
            self._by_id[conn.id] = conn

    def add(self, connection: Connection) -> None:
        """Register or replace a connection at runtime."""
        self._by_id[connection.id] = connection

    async def get(self, connection_id: str) -> Connection:
        conn = self._by_id.get(connection_id)
        if conn is None:
            raise ConnectionNotFoundError()
        return conn

    async def list_for_tenant(self, tenant_id: str) -> list[Connection]:
        return [c for c in self._by_id.values() if c.tenant_id == tenant_id]

    async def list_for_email(self, email: str) -> list[ConnectionInfo]:
        domain = email.lower().split("@", 1)[-1]
        tenant_id = self._domains.get(domain)
        if tenant_id is None:
            return []
        return [
            ConnectionInfo(
                connection_id=c.id,
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
