from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    EmailStr,
    Field,
    SecretStr,
    SerializeAsAny,
    field_validator,
)

CONNECTION_ID_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,63}$"


class PrincipalType(StrEnum):
    USER = "user"
    SERVICE = "service"


class Principal(BaseModel):
    """Anything that authenticates: a human user or a service."""

    id: str
    type: PrincipalType
    tenant_id: str
    email: EmailStr | None = None
    name: str | None = None
    roles: list[str] = Field(default_factory=list)
    scopes: list[str] = Field(default_factory=list)


class RawIdentity(BaseModel):
    """Unmapped claims exactly as the protocol produced them."""

    claims: dict[str, Any]


class CanonicalIdentity(BaseModel):
    """The single normalized shape every protocol output is mapped into."""

    external_id: str = Field(min_length=1)  # stable IdP subject (sub / NameID) - never email
    email: EmailStr | None = None
    name: str | None = None
    roles: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)  # extracted via Mapping.extra
    raw: dict[str, Any] = Field(default_factory=dict)  # full original claims, always preserved


class Mapping(BaseModel):
    """Claim paths (dotted keys, e.g. "user.id") -> canonical fields. Never eval."""

    external_id: str = "sub"
    email: str | None = "email"
    name: str | None = "name"
    roles: str | None = None
    extra: dict[str, str] = Field(default_factory=dict)  # attribute name -> claim path
    transforms: dict[str, str] = Field(default_factory=dict)  # field name -> transform name


class ProtocolSettings(BaseModel):
    """Base for per-protocol connection settings. Subclass + @register_settings to extend."""

    kind: str


_SETTINGS_KINDS: dict[str, type[ProtocolSettings]] = {}


def register_settings(cls: type[ProtocolSettings]) -> type[ProtocolSettings]:
    kind_default = cls.model_fields["kind"].default
    if not isinstance(kind_default, str):
        msg = f"{cls.__name__} must declare a string default for 'kind'"
        raise TypeError(msg)
    _SETTINGS_KINDS[kind_default] = cls
    return cls


@register_settings
class OidcSettings(ProtocolSettings):
    kind: Literal["oidc"] = "oidc"
    issuer: AnyHttpUrl
    client_id: str
    client_secret: SecretStr
    scopes: list[str] = Field(default_factory=lambda: ["openid", "email", "profile"])
    fetch_userinfo: bool = False  # merge userinfo_endpoint claims over id_token claims


@register_settings
class OAuth2Settings(ProtocolSettings):
    kind: Literal["oauth2"] = "oauth2"
    authorize_url: AnyHttpUrl
    token_url: AnyHttpUrl
    userinfo_url: AnyHttpUrl | None = None
    client_id: str
    client_secret: SecretStr
    scopes: list[str] = Field(default_factory=list)


class Connection(BaseModel):
    """One configured IdP for a tenant: protocol + settings + claim mapping."""

    id: str = Field(pattern=CONNECTION_ID_PATTERN)  # path-safe: used in /auth/{id}/login
    tenant_id: str
    display_name: str
    settings: SerializeAsAny[ProtocolSettings]
    mapping: Mapping = Field(default_factory=Mapping)

    @field_validator("settings", mode="before")
    @classmethod
    def _resolve_settings(cls, value: Any) -> Any:
        if isinstance(value, dict):
            kind = value.get("kind")
            settings_cls = _SETTINGS_KINDS.get(kind) if isinstance(kind, str) else None
            if settings_cls is None:
                msg = f"unknown protocol kind {kind!r}"
                raise ValueError(msg)
            return settings_cls.model_validate(value)
        if type(value) is ProtocolSettings:
            msg = "settings must be a concrete ProtocolSettings subclass"
            raise ValueError(msg)
        return value


class ConnectionInfo(BaseModel):
    """Public discovery shape - uniform regardless of protocol (anti-enumeration)."""

    connection_id: str
    display_name: str
    kind: str


class TokenClaims(BaseModel):
    """Verified, typed view of an authub JWT payload."""

    sub: str
    token_type: PrincipalType
    tenant_id: str
    email: EmailStr | None = None
    name: str | None = None
    roles: list[str] = Field(default_factory=list)
    scopes: list[str] = Field(default_factory=list)
    jti: str
    iat: int
    exp: int | None = None
    claims: dict[str, Any] = Field(default_factory=dict)  # full raw payload

    def to_principal(self) -> Principal:
        return Principal(
            id=self.sub,
            type=self.token_type,
            tenant_id=self.tenant_id,
            email=self.email,
            name=self.name,
            roles=list(self.roles),
            scopes=list(self.scopes),
        )


class SessionCookieConfig(BaseModel):
    """Opt-in browser-session behavior for the callback (see web/router.py)."""

    cookie_name: str = "__authub_session"
    csrf_cookie_name: str = "__authub_csrf"
    csrf_header_name: str = "x-authub-csrf"
    max_age: int = 8 * 3600
    secure: bool = True
    samesite: Literal["lax", "strict"] = "lax"
    success_redirect: bool = True  # redirect to return_to instead of returning JSON
