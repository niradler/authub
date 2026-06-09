from __future__ import annotations

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

__version__ = "0.1.0"


def get_version() -> str:
    return __version__


__all__ = [
    "Authub",
    "AuthubError",
    "CanonicalIdentity",
    "Connection",
    "ConnectionInfo",
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
    "SessionCookieConfig",
    "TokenClaims",
    "get_version",
    "register_settings",
    "register_transform",
]
