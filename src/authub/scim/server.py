from __future__ import annotations

import re
from functools import cached_property
from typing import Any

from fastapi import APIRouter, FastAPI
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from authub.scim.auth import ScimAuthenticator
from authub.scim.models import (
    SCHEMA_GROUP,
    SCHEMA_LIST_RESPONSE,
    SCHEMA_USER,
    ListResponse,
    PatchRequest,
    ScimError,
    ScimGroup,
    ScimUser,
)
from authub.scim.store import (
    InMemoryScimGroupStore,
    InMemoryScimUserStore,
    ScimConflictError,
    ScimGroupStore,
    ScimInvalidPathError,
    ScimUserStore,
)

_SCIM_CONTENT_TYPE = "application/scim+json"
_MAX_PAGE_SIZE = 200

_FILTER_RE = re.compile(
    r'^(?P<attr>\w+)\s+eq\s+["\'](?P<value>[^"\']*)["\']$',
    re.IGNORECASE,
)

_ALLOWED_USER_FILTER_ATTRS = frozenset({"userName", "externalId"})
_ALLOWED_GROUP_FILTER_ATTRS = frozenset({"displayName"})


def _scim_response(data: dict[str, Any], status: int = 200) -> JSONResponse:
    return JSONResponse(content=data, status_code=status, media_type=_SCIM_CONTENT_TYPE)


def _error(status: int, detail: str, scim_type: str | None = None) -> JSONResponse:
    err = ScimError(status=str(status), detail=detail, scim_type=scim_type)
    return err.to_response()


def _stamp_location(data: dict[str, Any], kind: str, prefix: str) -> str:
    location = f"{prefix}/{kind}/{data.get('id', '')}"
    if isinstance(data.get("meta"), dict):
        data["meta"]["location"] = location
    return location


def _parse_filter(
    filter_str: str | None, allowed_attrs: frozenset[str]
) -> tuple[str | None, str | None, JSONResponse | None]:
    if not filter_str:
        return None, None, None
    m = _FILTER_RE.match(filter_str.strip())
    if m is None:
        return None, None, _error(400, "Unsupported filter expression", "invalidFilter")
    attr = m.group("attr")
    if attr not in allowed_attrs:
        return None, None, _error(400, f"Filtering on {attr!r} is not supported", "invalidFilter")
    return attr, m.group("value"), None


def _bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return None


class ScimServer:
    """SCIM 2.0 inbound provisioning server for Users and Groups.

    Supports multi-tenant isolation via a ScimAuthenticator that resolves
    bearer tokens to tenant IDs.

    Args:
        users: User store. Defaults to InMemoryScimUserStore.
        groups: Group store. Defaults to InMemoryScimGroupStore.
        authenticator: Required bearer-token resolver.
    """

    def __init__(
        self,
        *,
        authenticator: ScimAuthenticator,
        users: ScimUserStore | None = None,
        groups: ScimGroupStore | None = None,
    ) -> None:
        self.authenticator = authenticator
        self.users: ScimUserStore = users if users is not None else InMemoryScimUserStore()
        self.groups: ScimGroupStore = groups if groups is not None else InMemoryScimGroupStore()
        self._prefix: str = "/scim/v2"

    async def _resolve_tenant(
        self, request: Request
    ) -> tuple[str, JSONResponse] | tuple[str, None]:
        token = _bearer_token(request)
        if token is None:
            return "", _error(401, "Bearer token required")
        tenant_id = await self.authenticator.resolve(token)
        if tenant_id is None:
            return "", _error(401, "Invalid bearer token")
        return tenant_id, None

    @cached_property
    def router(self) -> APIRouter:
        router = APIRouter(tags=["scim"])

        @router.get("/ServiceProviderConfig")
        async def service_provider_config() -> Response:
            body: dict[str, Any] = {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
                "documentationUri": "",
                "patch": {"supported": True},
                "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
                "filter": {"supported": True, "maxResults": 200},
                "changePassword": {"supported": False},
                "sort": {"supported": False},
                "etag": {"supported": False},
                "authenticationSchemes": [
                    {
                        "type": "oauthbearertoken",
                        "name": "OAuth Bearer Token",
                        "description": "Authentication scheme using OAuth2 bearer token",
                    }
                ],
            }
            return _scim_response(body)

        @router.get("/ResourceTypes")
        async def resource_types() -> Response:
            body: dict[str, Any] = {
                "schemas": [SCHEMA_LIST_RESPONSE],
                "totalResults": 2,
                "Resources": [
                    {
                        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                        "id": "User",
                        "name": "User",
                        "endpoint": "/Users",
                        "schema": SCHEMA_USER,
                    },
                    {
                        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                        "id": "Group",
                        "name": "Group",
                        "endpoint": "/Groups",
                        "schema": SCHEMA_GROUP,
                    },
                ],
            }
            return _scim_response(body)

        @router.get("/Schemas")
        async def schemas() -> Response:
            body: dict[str, Any] = {
                "schemas": [SCHEMA_LIST_RESPONSE],
                "totalResults": 2,
                "Resources": [
                    {
                        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
                        "id": SCHEMA_USER,
                        "name": "User",
                        "description": "User Account",
                    },
                    {
                        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
                        "id": SCHEMA_GROUP,
                        "name": "Group",
                        "description": "Group",
                    },
                ],
            }
            return _scim_response(body)

        @router.post("/Users")
        async def create_user(request: Request) -> Response:
            tenant_id, err = await self._resolve_tenant(request)
            if err is not None:
                return err
            body = await request.json()
            try:
                user = ScimUser.model_validate(body)
            except Exception:
                return _error(400, "Invalid user payload")
            try:
                created = await self.users.create(tenant_id, user)
            except ScimConflictError:
                return _error(409, "User with this userName already exists", "uniqueness")
            data = created.model_dump(by_alias=True, exclude_none=True)
            location = _stamp_location(data, "Users", self._prefix)
            resp = _scim_response(data, 201)
            resp.headers["Location"] = location
            return resp

        @router.get("/Users/{user_id}")
        async def get_user(user_id: str, request: Request) -> Response:
            tenant_id, err = await self._resolve_tenant(request)
            if err is not None:
                return err
            user = await self.users.get(tenant_id, user_id)
            if user is None:
                return _error(404, "User not found")
            data = user.model_dump(by_alias=True, exclude_none=True)
            _stamp_location(data, "Users", self._prefix)
            return _scim_response(data)

        @router.get("/Users")
        async def list_users(request: Request) -> Response:
            tenant_id, err = await self._resolve_tenant(request)
            if err is not None:
                return err
            params = request.query_params
            filter_str = params.get("filter")
            try:
                start_index = max(1, int(params.get("startIndex", "1")))
                count = min(_MAX_PAGE_SIZE, max(0, int(params.get("count", "100"))))
            except ValueError:
                return _error(400, "startIndex and count must be integers")
            filter_attr, filter_value, filter_err = _parse_filter(
                filter_str, _ALLOWED_USER_FILTER_ATTRS
            )
            if filter_err is not None:
                return filter_err
            users, total = await self.users.list(
                tenant_id,
                filter_attr=filter_attr,
                filter_value=filter_value,
                start_index=start_index,
                count=count,
            )
            resources = [u.model_dump(by_alias=True, exclude_none=True) for u in users]
            resp_obj = ListResponse(
                total_results=total,
                start_index=start_index,
                items_per_page=len(resources),
                resources=resources,
            )
            return _scim_response(resp_obj.model_dump(by_alias=True))

        @router.put("/Users/{user_id}")
        async def replace_user(user_id: str, request: Request) -> Response:
            tenant_id, err = await self._resolve_tenant(request)
            if err is not None:
                return err
            body = await request.json()
            try:
                user = ScimUser.model_validate(body)
            except Exception:
                return _error(400, "Invalid user payload")
            try:
                updated = await self.users.replace(tenant_id, user_id, user)
            except ScimConflictError:
                return _error(409, "User with this userName already exists", "uniqueness")
            except (ValidationError, ValueError) as exc:
                return _error(400, str(exc), "invalidValue")
            if updated is None:
                return _error(404, "User not found")
            data = updated.model_dump(by_alias=True, exclude_none=True)
            _stamp_location(data, "Users", self._prefix)
            return _scim_response(data)

        @router.patch("/Users/{user_id}")
        async def patch_user(user_id: str, request: Request) -> Response:
            tenant_id, err = await self._resolve_tenant(request)
            if err is not None:
                return err
            body = await request.json()
            try:
                patch_req = PatchRequest.model_validate(body)
            except Exception:
                return _error(400, "Invalid patch payload")
            try:
                updated = await self.users.patch(tenant_id, user_id, patch_req.operations)
            except (ValidationError, ValueError) as exc:
                return _error(400, str(exc), "invalidValue")
            if updated is None:
                return _error(404, "User not found")
            data = updated.model_dump(by_alias=True, exclude_none=True)
            _stamp_location(data, "Users", self._prefix)
            return _scim_response(data)

        @router.delete("/Users/{user_id}")
        async def delete_user(user_id: str, request: Request) -> Response:
            tenant_id, err = await self._resolve_tenant(request)
            if err is not None:
                return err
            deleted = await self.users.delete(tenant_id, user_id)
            if not deleted:
                return _error(404, "User not found")
            return Response(status_code=204)

        @router.post("/Groups")
        async def create_group(request: Request) -> Response:
            tenant_id, err = await self._resolve_tenant(request)
            if err is not None:
                return err
            body = await request.json()
            try:
                group = ScimGroup.model_validate(body)
            except Exception:
                return _error(400, "Invalid group payload")
            created = await self.groups.create(tenant_id, group)
            data = created.model_dump(by_alias=True, exclude_none=True)
            location = _stamp_location(data, "Groups", self._prefix)
            resp = _scim_response(data, 201)
            resp.headers["Location"] = location
            return resp

        @router.get("/Groups/{group_id}")
        async def get_group(group_id: str, request: Request) -> Response:
            tenant_id, err = await self._resolve_tenant(request)
            if err is not None:
                return err
            group = await self.groups.get(tenant_id, group_id)
            if group is None:
                return _error(404, "Group not found")
            data = group.model_dump(by_alias=True, exclude_none=True)
            _stamp_location(data, "Groups", self._prefix)
            return _scim_response(data)

        @router.get("/Groups")
        async def list_groups(request: Request) -> Response:
            tenant_id, err = await self._resolve_tenant(request)
            if err is not None:
                return err
            params = request.query_params
            filter_str = params.get("filter")
            try:
                start_index = max(1, int(params.get("startIndex", "1")))
                count = min(_MAX_PAGE_SIZE, max(0, int(params.get("count", "100"))))
            except ValueError:
                return _error(400, "startIndex and count must be integers")
            filter_attr, filter_value, filter_err = _parse_filter(
                filter_str, _ALLOWED_GROUP_FILTER_ATTRS
            )
            if filter_err is not None:
                return filter_err
            groups, total = await self.groups.list(
                tenant_id,
                filter_attr=filter_attr,
                filter_value=filter_value,
                start_index=start_index,
                count=count,
            )
            resources = [g.model_dump(by_alias=True, exclude_none=True) for g in groups]
            resp_obj = ListResponse(
                total_results=total,
                start_index=start_index,
                items_per_page=len(resources),
                resources=resources,
            )
            return _scim_response(resp_obj.model_dump(by_alias=True))

        @router.put("/Groups/{group_id}")
        async def replace_group(group_id: str, request: Request) -> Response:
            tenant_id, err = await self._resolve_tenant(request)
            if err is not None:
                return err
            body = await request.json()
            try:
                group = ScimGroup.model_validate(body)
            except Exception:
                return _error(400, "Invalid group payload")
            try:
                updated = await self.groups.replace(tenant_id, group_id, group)
            except (ValidationError, ValueError) as exc:
                return _error(400, str(exc), "invalidValue")
            if updated is None:
                return _error(404, "Group not found")
            data = updated.model_dump(by_alias=True, exclude_none=True)
            _stamp_location(data, "Groups", self._prefix)
            return _scim_response(data)

        @router.patch("/Groups/{group_id}")
        async def patch_group(group_id: str, request: Request) -> Response:
            tenant_id, err = await self._resolve_tenant(request)
            if err is not None:
                return err
            body = await request.json()
            try:
                patch_req = PatchRequest.model_validate(body)
            except Exception:
                return _error(400, "Invalid patch payload")
            try:
                updated = await self.groups.patch(tenant_id, group_id, patch_req.operations)
            except ScimInvalidPathError as exc:
                return _error(400, str(exc), "invalidPath")
            except (ValidationError, ValueError) as exc:
                return _error(400, str(exc), "invalidValue")
            if updated is None:
                return _error(404, "Group not found")
            data = updated.model_dump(by_alias=True, exclude_none=True)
            _stamp_location(data, "Groups", self._prefix)
            return _scim_response(data)

        @router.delete("/Groups/{group_id}")
        async def delete_group(group_id: str, request: Request) -> Response:
            tenant_id, err = await self._resolve_tenant(request)
            if err is not None:
                return err
            deleted = await self.groups.delete(tenant_id, group_id)
            if not deleted:
                return _error(404, "Group not found")
            return Response(status_code=204)

        return router

    def attach(self, app: FastAPI, prefix: str = "/scim/v2") -> None:
        """Mount the SCIM router onto a FastAPI application.

        Args:
            app: The FastAPI application to mount onto.
            prefix: URL prefix for all SCIM routes (default ``"/scim/v2"``).
        """
        self._prefix = prefix.rstrip("/")
        app.include_router(self.router, prefix=self._prefix)
