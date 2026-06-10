from __future__ import annotations

from importlib import metadata

from authub.errors import AuthubError
from authub.hub import Authub
from authub.mapping import Mapper, register_transform
from authub.models import (
    CanonicalIdentity,
    Connection,
    ConnectionInfo,
    Mapping,
    OAuth2Settings,
    OidcSettings,
    Principal,
    PrincipalType,
    ProtocolSettings,
    RawIdentity,
    SamlSettings,
    SessionCookieConfig,
    TokenClaims,
    register_settings,
)
from authub.plugins import Plugin
from authub.scim import (
    InMemoryScimGroupStore,
    InMemoryScimUserStore,
    ScimAuthenticator,
    ScimServer,
    StaticTokenAuthenticator,
)

try:
    __version__ = metadata.version("authub")
except metadata.PackageNotFoundError:
    __version__ = "0.0.0"

__all__ = [
    "Authub",
    "AuthubError",
    "CanonicalIdentity",
    "Connection",
    "ConnectionInfo",
    "InMemoryScimGroupStore",
    "InMemoryScimUserStore",
    "Mapper",
    "Mapping",
    "OAuth2Settings",
    "OidcSettings",
    "Plugin",
    "Principal",
    "PrincipalType",
    "ProtocolSettings",
    "RawIdentity",
    "SamlSettings",
    "ScimAuthenticator",
    "ScimServer",
    "SessionCookieConfig",
    "StaticTokenAuthenticator",
    "TokenClaims",
    "register_settings",
    "register_transform",
]
