from __future__ import annotations

import pytest
from pydantic import AnyHttpUrl, SecretStr, TypeAdapter, ValidationError

from authub.models import (
    CanonicalIdentity,
    Connection,
    Mapping,
    OidcSettings,
    Principal,
    PrincipalType,
    ProtocolSettings,
    TokenClaims,
    register_settings,
)

_url = TypeAdapter(AnyHttpUrl)


def make_oidc() -> OidcSettings:
    return OidcSettings(
        issuer=_url.validate_python("https://accounts.google.com"),
        client_id="cid",
        client_secret=SecretStr("cs"),
    )


def test_oidc_settings_defaults() -> None:
    s = make_oidc()
    assert s.kind == "oidc"
    assert s.scopes == ["openid", "email", "profile"]
    assert "cs" not in repr(s)  # SecretStr never leaks


def test_connection_resolves_settings_from_dict() -> None:
    conn = Connection.model_validate(
        {
            "id": "acme-google",
            "tenant_id": "acme",
            "display_name": "Google",
            "settings": {
                "kind": "oidc",
                "issuer": "https://accounts.google.com",
                "client_id": "cid",
                "client_secret": "cs",
            },
        }
    )
    assert isinstance(conn.settings, OidcSettings)


def test_connection_rejects_unknown_kind() -> None:
    with pytest.raises(ValidationError, match="unknown protocol kind"):
        Connection.model_validate(
            {
                "id": "x",
                "tenant_id": "t",
                "display_name": "X",
                "settings": {"kind": "carrier-pigeon"},
            }
        )


def test_connection_roundtrip_serializes_subclass_fields() -> None:
    conn = Connection(
        id="c1", tenant_id="t", display_name="C", settings=make_oidc(), mapping=Mapping()
    )
    dumped = conn.model_dump(mode="json")
    assert dumped["settings"]["issuer"].rstrip("/") == "https://accounts.google.com"
    again = Connection.model_validate(dumped)
    assert isinstance(again.settings, OidcSettings)


def test_connection_id_pattern() -> None:
    with pytest.raises(ValidationError):
        Connection(id="Bad/Id", tenant_id="t", display_name="x", settings=make_oidc())


def test_custom_settings_registration() -> None:
    @register_settings
    class MagicSettings(ProtocolSettings):
        kind: str = "magic"
        wand: str

    conn = Connection.model_validate(
        {
            "id": "m1",
            "tenant_id": "t",
            "display_name": "M",
            "settings": {"kind": "magic", "wand": "elder"},
        }
    )
    assert isinstance(conn.settings, MagicSettings)


def test_token_claims_to_principal() -> None:
    claims = TokenClaims(
        sub="usr_1",
        token_type=PrincipalType.USER,
        tenant_id="acme",
        email="a@b.co",
        roles=["admin"],
        jti="j1",
        iat=1,
        exp=2,
        claims={"sub": "usr_1"},
    )
    p = claims.to_principal()
    assert p.id == "usr_1" and p.type is PrincipalType.USER and p.roles == ["admin"]


def test_canonical_identity_requires_external_id() -> None:
    with pytest.raises(ValidationError):
        CanonicalIdentity(external_id="", raw={})


def test_principal_defaults() -> None:
    p = Principal(id="svc_1", type=PrincipalType.SERVICE, tenant_id="t")
    assert p.scopes == [] and p.roles == [] and p.email is None
