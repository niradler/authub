from __future__ import annotations

import re
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from uuid import uuid4

from authub.scim.models import PatchOperation, ScimGroup, ScimMember, ScimMeta, ScimUser


class ScimConflictError(Exception):
    """Raised when a duplicate userName already exists within a tenant."""


class ScimInvalidPathError(Exception):
    """Raised when a PATCH path expression cannot be interpreted."""


_MEMBER_FILTER_RE = re.compile(
    r'^members\[value\s+eq\s+["\'](?P<id>[^"\']+)["\']\]$',
    re.IGNORECASE,
)


class ScimNotFoundError(Exception):
    """Raised when a resource cannot be found."""


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


class ScimUserStore(ABC):
    """Abstract tenant-scoped store for SCIM User resources."""

    @abstractmethod
    async def create(self, tenant_id: str, user: ScimUser) -> ScimUser:
        """Persist a new user. Assign server id and meta.

        Raises ScimConflictError on duplicate userName within the tenant.
        """
        ...

    @abstractmethod
    async def get(self, tenant_id: str, user_id: str) -> ScimUser | None:
        """Return the user by id within the tenant, or None."""
        ...

    @abstractmethod
    async def replace(self, tenant_id: str, user_id: str, user: ScimUser) -> ScimUser | None:
        """Replace all attributes (PUT semantics). Return None if absent."""
        ...

    @abstractmethod
    async def patch(
        self, tenant_id: str, user_id: str, ops: list[PatchOperation]
    ) -> ScimUser | None:
        """Apply patch operations. Return None if absent."""
        ...

    @abstractmethod
    async def delete(self, tenant_id: str, user_id: str) -> bool:
        """Delete the user. Return True if deleted, False if not found."""
        ...

    @abstractmethod
    async def list(
        self,
        tenant_id: str,
        *,
        filter_attr: str | None,
        filter_value: str | None,
        start_index: int,
        count: int,
    ) -> tuple[list[ScimUser], int]:
        """Return a page of users and the totalResults count."""
        ...


class ScimGroupStore(ABC):
    """Abstract tenant-scoped store for SCIM Group resources."""

    @abstractmethod
    async def create(self, tenant_id: str, group: ScimGroup) -> ScimGroup:
        """Persist a new group. Assign server id and meta."""
        ...

    @abstractmethod
    async def get(self, tenant_id: str, group_id: str) -> ScimGroup | None:
        """Return the group by id within the tenant, or None."""
        ...

    @abstractmethod
    async def replace(self, tenant_id: str, group_id: str, group: ScimGroup) -> ScimGroup | None:
        """Replace all attributes (PUT semantics). Return None if absent."""
        ...

    @abstractmethod
    async def patch(
        self, tenant_id: str, group_id: str, ops: list[PatchOperation]
    ) -> ScimGroup | None:
        """Apply patch operations to the group. Return None if absent."""
        ...

    @abstractmethod
    async def delete(self, tenant_id: str, group_id: str) -> bool:
        """Delete the group. Return True if deleted, False if not found."""
        ...

    @abstractmethod
    async def list(
        self,
        tenant_id: str,
        *,
        filter_attr: str | None,
        filter_value: str | None,
        start_index: int,
        count: int,
    ) -> tuple[list[ScimGroup], int]:
        """Return a page of groups and the totalResults count."""
        ...


def _make_user_meta(location: str, created: str) -> ScimMeta:
    now = _now_iso()
    return ScimMeta(
        resource_type="User",
        created=created,
        last_modified=now,
        location=location,
        version=f'W/"{uuid4().hex[:8]}"',
    )


def _make_group_meta(location: str, created: str) -> ScimMeta:
    now = _now_iso()
    return ScimMeta(
        resource_type="Group",
        created=created,
        last_modified=now,
        location=location,
        version=f'W/"{uuid4().hex[:8]}"',
    )


class InMemoryScimUserStore(ScimUserStore):
    """In-process SCIM user store, keyed by (tenant_id, user_id).

    Not suitable for multi-instance deployments.
    """

    def __init__(self) -> None:
        self._users: dict[tuple[str, str], ScimUser] = {}

    def _by_tenant(self, tenant_id: str) -> list[ScimUser]:
        return [u for (tid, _), u in self._users.items() if tid == tenant_id]

    async def create(self, tenant_id: str, user: ScimUser) -> ScimUser:
        for existing in self._by_tenant(tenant_id):
            if existing.user_name == user.user_name:
                raise ScimConflictError(f"userName {user.user_name!r} already exists")
        user_id = f"usr_{uuid4().hex[:16]}"
        now = _now_iso()
        location = f"/scim/v2/Users/{user_id}"
        stored = user.model_copy(
            update={
                "id": user_id,
                "meta": _make_user_meta(location, now),
            }
        )
        self._users[(tenant_id, user_id)] = stored
        return stored

    async def get(self, tenant_id: str, user_id: str) -> ScimUser | None:
        return self._users.get((tenant_id, user_id))

    async def replace(self, tenant_id: str, user_id: str, user: ScimUser) -> ScimUser | None:
        existing = self._users.get((tenant_id, user_id))
        if existing is None:
            return None
        for (tid, uid), other in self._users.items():
            if tid == tenant_id and uid != user_id and other.user_name == user.user_name:
                raise ScimConflictError(f"userName {user.user_name!r} already exists")
        now = _now_iso()
        location = f"/scim/v2/Users/{user_id}"
        stored = user.model_copy(
            update={
                "id": user_id,
                "meta": ScimMeta(
                    resource_type="User",
                    created=existing.meta.created if existing.meta else now,
                    last_modified=now,
                    location=location,
                    version=f'W/"{uuid4().hex[:8]}"',
                ),
            }
        )
        self._users[(tenant_id, user_id)] = stored
        return stored

    async def patch(
        self, tenant_id: str, user_id: str, ops: list[PatchOperation]
    ) -> ScimUser | None:
        user = self._users.get((tenant_id, user_id))
        if user is None:
            return None
        data = user.model_dump(by_alias=False)
        for op in ops:
            normalized = op.op.lower()
            path = op.path
            value = op.value
            if normalized in ("replace", "add") and path is not None:
                data[_snake(path)] = value
            elif normalized == "remove" and path is not None:
                snake_path = _snake(path)
                data[snake_path] = False if snake_path == "active" else None
            elif normalized in ("add", "replace") and path is None and isinstance(value, dict):
                for k, v in value.items():
                    data[_snake(k)] = v
        now = _now_iso()
        location = f"/scim/v2/Users/{user_id}"
        meta_data = data.get("meta") or {}
        if isinstance(meta_data, ScimMeta):
            created = meta_data.created or now
        elif isinstance(meta_data, dict):
            created = meta_data.get("created") or now
        else:
            created = now
        data["meta"] = ScimMeta(
            resource_type="User",
            created=created,
            last_modified=now,
            location=location,
            version=f'W/"{uuid4().hex[:8]}"',
        )
        updated = ScimUser.model_validate(data)
        self._users[(tenant_id, user_id)] = updated
        return updated

    async def delete(self, tenant_id: str, user_id: str) -> bool:
        if (tenant_id, user_id) not in self._users:
            return False
        del self._users[(tenant_id, user_id)]
        return True

    async def list(
        self,
        tenant_id: str,
        *,
        filter_attr: str | None,
        filter_value: str | None,
        start_index: int,
        count: int,
    ) -> tuple[list[ScimUser], int]:
        all_users = self._by_tenant(tenant_id)
        if filter_attr is not None and filter_value is not None:
            all_users = [u for u in all_users if _user_attr(u, filter_attr) == filter_value]
        total = len(all_users)
        offset = max(0, start_index - 1)
        page = all_users[offset : offset + count]
        return page, total


def _user_attr(user: ScimUser, attr: str) -> str | None:
    if attr == "userName":
        return user.user_name
    if attr == "externalId":
        return user.external_id
    return None


def _group_attr(group: ScimGroup, attr: str) -> str | None:
    if attr == "displayName":
        return group.display_name
    return None


def _snake(name: str) -> str:
    mapping: dict[str, str] = {
        "userName": "user_name",
        "externalId": "external_id",
        "displayName": "display_name",
        "givenName": "given_name",
        "familyName": "family_name",
        "lastModified": "last_modified",
        "resourceType": "resource_type",
    }
    return mapping.get(name, name)


class InMemoryScimGroupStore(ScimGroupStore):
    """In-process SCIM group store, keyed by (tenant_id, group_id).

    Not suitable for multi-instance deployments.
    """

    def __init__(self) -> None:
        self._groups: dict[tuple[str, str], ScimGroup] = {}

    def _by_tenant(self, tenant_id: str) -> list[ScimGroup]:
        return [g for (tid, _), g in self._groups.items() if tid == tenant_id]

    async def create(self, tenant_id: str, group: ScimGroup) -> ScimGroup:
        group_id = f"grp_{uuid4().hex[:16]}"
        now = _now_iso()
        location = f"/scim/v2/Groups/{group_id}"
        stored = group.model_copy(
            update={
                "id": group_id,
                "meta": _make_group_meta(location, now),
            }
        )
        self._groups[(tenant_id, group_id)] = stored
        return stored

    async def get(self, tenant_id: str, group_id: str) -> ScimGroup | None:
        return self._groups.get((tenant_id, group_id))

    async def replace(self, tenant_id: str, group_id: str, group: ScimGroup) -> ScimGroup | None:
        existing = self._groups.get((tenant_id, group_id))
        if existing is None:
            return None
        now = _now_iso()
        location = f"/scim/v2/Groups/{group_id}"
        stored = group.model_copy(
            update={
                "id": group_id,
                "meta": ScimMeta(
                    resource_type="Group",
                    created=existing.meta.created if existing.meta else now,
                    last_modified=now,
                    location=location,
                    version=f'W/"{uuid4().hex[:8]}"',
                ),
            }
        )
        self._groups[(tenant_id, group_id)] = stored
        return stored

    async def patch(
        self, tenant_id: str, group_id: str, ops: list[PatchOperation]
    ) -> ScimGroup | None:
        group = self._groups.get((tenant_id, group_id))
        if group is None:
            return None
        members = list(group.members)
        display_name = group.display_name
        for op in ops:
            normalized = op.op.lower()
            path = op.path
            value = op.value
            if path == "members":
                if normalized == "add":
                    new_members = _parse_member_list(value)
                    existing_ids = {m.value for m in members}
                    for m in new_members:
                        if m.value not in existing_ids:
                            members.append(m)
                elif normalized == "remove":
                    remove_ids = {m["value"] for m in (value or []) if isinstance(m, dict)}
                    members = [m for m in members if m.value not in remove_ids]
                elif normalized == "replace":
                    members = _parse_member_list(value)
            elif path is not None and path.startswith("members["):
                if normalized == "remove":
                    filter_match = _MEMBER_FILTER_RE.match(path)
                    if filter_match is None:
                        raise ScimInvalidPathError(f"Unsupported member filter path: {path!r}")
                    target_id = filter_match.group("id")
                    members = [mem for mem in members if mem.value != target_id]
                else:
                    raise ScimInvalidPathError(
                        f"Unsupported op {normalized!r} on member filter path"
                    )
            elif path == "displayName" and normalized in ("add", "replace"):
                display_name = str(value)
        now = _now_iso()
        location = f"/scim/v2/Groups/{group_id}"
        updated = group.model_copy(
            update={
                "members": members,
                "display_name": display_name,
                "meta": ScimMeta(
                    resource_type="Group",
                    created=group.meta.created if group.meta else now,
                    last_modified=now,
                    location=location,
                    version=f'W/"{uuid4().hex[:8]}"',
                ),
            }
        )
        self._groups[(tenant_id, group_id)] = updated
        return updated

    async def delete(self, tenant_id: str, group_id: str) -> bool:
        if (tenant_id, group_id) not in self._groups:
            return False
        del self._groups[(tenant_id, group_id)]
        return True

    async def list(
        self,
        tenant_id: str,
        *,
        filter_attr: str | None,
        filter_value: str | None,
        start_index: int,
        count: int,
    ) -> tuple[list[ScimGroup], int]:
        all_groups = self._by_tenant(tenant_id)
        if filter_attr is not None and filter_value is not None:
            all_groups = [g for g in all_groups if _group_attr(g, filter_attr) == filter_value]
        total = len(all_groups)
        offset = max(0, start_index - 1)
        page = all_groups[offset : offset + count]
        return page, total


def _parse_member_list(value: object) -> list[ScimMember]:
    if not isinstance(value, list):
        return []
    result: list[ScimMember] = []
    for item in value:
        if isinstance(item, dict):
            result.append(ScimMember.model_validate(item))
        elif isinstance(item, ScimMember):
            result.append(item)
    return result
