from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from starlette.responses import JSONResponse

SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCHEMA_LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCHEMA_PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"


class ScimName(BaseModel):
    """SCIM name sub-object."""

    model_config = ConfigDict(populate_by_name=True)

    formatted: str | None = None
    given_name: str | None = Field(default=None, alias="givenName")
    family_name: str | None = Field(default=None, alias="familyName")


class ScimEmail(BaseModel):
    """SCIM email entry."""

    model_config = ConfigDict(populate_by_name=True)

    value: str
    type: str | None = None
    primary: bool = False


class ScimMeta(BaseModel):
    """SCIM meta sub-object."""

    model_config = ConfigDict(populate_by_name=True)

    resource_type: str | None = Field(default=None, alias="resourceType")
    created: str | None = None
    last_modified: str | None = Field(default=None, alias="lastModified")
    location: str | None = None
    version: str | None = None


class ScimUser(BaseModel):
    """SCIM User resource."""

    model_config = ConfigDict(populate_by_name=True)

    schemas: list[str] = Field(default_factory=lambda: [SCHEMA_USER])
    id: str | None = None
    external_id: str | None = Field(default=None, alias="externalId")
    user_name: str = Field(alias="userName")
    name: ScimName | None = None
    display_name: str | None = Field(default=None, alias="displayName")
    emails: list[ScimEmail] = Field(default_factory=list)
    active: bool = True
    meta: ScimMeta | None = None


class ScimMember(BaseModel):
    """SCIM group member reference."""

    model_config = ConfigDict(populate_by_name=True)

    value: str
    ref: str | None = Field(default=None, alias="$ref")
    display: str | None = None
    type: str | None = None


class ScimGroup(BaseModel):
    """SCIM Group resource."""

    model_config = ConfigDict(populate_by_name=True)

    schemas: list[str] = Field(default_factory=lambda: [SCHEMA_GROUP])
    id: str | None = None
    display_name: str = Field(alias="displayName")
    members: list[ScimMember] = Field(default_factory=list)
    meta: ScimMeta | None = None


class ListResponse(BaseModel):
    """SCIM ListResponse envelope."""

    model_config = ConfigDict(populate_by_name=True)

    schemas: list[str] = Field(default_factory=lambda: [SCHEMA_LIST_RESPONSE])
    total_results: int = Field(alias="totalResults")
    start_index: int = Field(default=1, alias="startIndex")
    items_per_page: int = Field(alias="itemsPerPage")
    resources: list[Any] = Field(default_factory=list, alias="Resources")


class PatchOpEnum(StrEnum):
    ADD = "add"
    REMOVE = "remove"
    REPLACE = "replace"


class PatchOperation(BaseModel):
    """A single SCIM PATCH operation."""

    model_config = ConfigDict(populate_by_name=True)

    op: str
    path: str | None = None
    value: Any = None

    @property
    def op_normalized(self) -> str:
        return self.op.lower()


class PatchRequest(BaseModel):
    """SCIM PatchOp request body."""

    model_config = ConfigDict(populate_by_name=True)

    schemas: list[str] = Field(default_factory=lambda: [SCHEMA_PATCH_OP])
    operations: list[PatchOperation] = Field(alias="Operations")


class ScimError(BaseModel):
    """SCIM error response body."""

    model_config = ConfigDict(populate_by_name=True)

    schemas: list[str] = Field(default_factory=lambda: [SCHEMA_ERROR])
    status: str
    scim_type: str | None = Field(default=None, alias="scimType")
    detail: str | None = None

    def to_response(self) -> JSONResponse:
        return JSONResponse(
            content=self.model_dump(by_alias=True, exclude_none=True),
            status_code=int(self.status),
            media_type="application/scim+json",
        )
