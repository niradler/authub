from __future__ import annotations

from pydantic import SecretStr

from authub.models import Mapping, OAuth2Settings, OidcSettings, SamlSettings

GITHUB_MAPPING = Mapping(external_id="id", email="email", name="name")


def oidc(
    issuer: str,
    client_id: str,
    client_secret: str,
    *,
    scopes: list[str] | None = None,
    fetch_userinfo: bool = False,
) -> OidcSettings:
    """Generic OIDC preset. Defaults to ``openid email profile`` scopes."""
    return OidcSettings(
        issuer=issuer,  # type: ignore[arg-type]
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        scopes=scopes if scopes is not None else ["openid", "email", "profile"],
        fetch_userinfo=fetch_userinfo,
    )


def oauth2(
    *,
    authorize_url: str,
    token_url: str,
    client_id: str,
    client_secret: str,
    userinfo_url: str | None = None,
    scopes: list[str] | None = None,
) -> OAuth2Settings:
    """Generic OAuth2 preset for providers that do not support OIDC discovery."""
    return OAuth2Settings(
        authorize_url=authorize_url,  # type: ignore[arg-type]
        token_url=token_url,  # type: ignore[arg-type]
        userinfo_url=userinfo_url,  # type: ignore[arg-type]
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        scopes=scopes or [],
    )


def google(client_id: str, client_secret: str) -> OidcSettings:
    """Google OIDC preset using ``accounts.google.com``."""
    return oidc("https://accounts.google.com", client_id, client_secret)


def okta(domain: str, client_id: str, client_secret: str) -> OidcSettings:
    """Okta OIDC preset. ``domain`` is the Okta tenant hostname (e.g. ``acme.okta.com``)."""
    return oidc(f"https://{domain}", client_id, client_secret)


def auth0(domain: str, client_id: str, client_secret: str) -> OidcSettings:
    """Auth0 OIDC preset. ``domain`` is the Auth0 tenant hostname (e.g. ``acme.auth0.com``)."""
    return oidc(f"https://{domain}", client_id, client_secret)


def entra(tenant_id: str, client_id: str, client_secret: str) -> OidcSettings:
    """Microsoft Entra ID (Azure AD) OIDC preset using the v2.0 tenant-specific endpoint."""
    return oidc(
        f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        client_id,
        client_secret,
    )


def gitlab(
    client_id: str, client_secret: str, base_url: str = "https://gitlab.com"
) -> OidcSettings:
    """GitLab OIDC preset; pass ``base_url`` for self-hosted instances."""
    return oidc(base_url, client_id, client_secret)


def github(client_id: str, client_secret: str) -> OAuth2Settings:
    """GitHub OAuth2 preset (non-OIDC) with ``read:user`` and ``user:email`` scopes."""
    return oauth2(
        authorize_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        userinfo_url="https://api.github.com/user",
        client_id=client_id,
        client_secret=client_secret,
        scopes=["read:user", "user:email"],
    )


def authub_idp(issuer: str, client_id: str, client_secret: str) -> OidcSettings:
    """OIDC preset pointing at an embedded ``authub.idp.AuthubIdp`` instance."""
    return oidc(issuer, client_id, client_secret)


SAML_MAPPING = Mapping(external_id="name_id", email="mail", name="cn")


def saml(
    *,
    sp_entity_id: str,
    idp_metadata_xml: str | None = None,
    idp_metadata_url: str | None = None,
    idp_entity_id: str | None = None,
    want_assertions_signed: bool = True,
) -> SamlSettings:
    """SAML 2.0 SP preset. Provide exactly one of ``idp_metadata_xml`` or ``idp_metadata_url``."""
    return SamlSettings(
        sp_entity_id=sp_entity_id,
        idp_metadata_xml=idp_metadata_xml,
        idp_metadata_url=idp_metadata_url,  # type: ignore[arg-type]
        idp_entity_id=idp_entity_id,
        want_assertions_signed=want_assertions_signed,
    )
