from __future__ import annotations

from pydantic import SecretStr

from authub.models import Mapping, OAuth2Settings, OidcSettings

GITHUB_MAPPING = Mapping(external_id="id", email="email", name="name")


def oidc(
    issuer: str,
    client_id: str,
    client_secret: str,
    *,
    scopes: list[str] | None = None,
    fetch_userinfo: bool = False,
) -> OidcSettings:
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
    return OAuth2Settings(
        authorize_url=authorize_url,  # type: ignore[arg-type]
        token_url=token_url,  # type: ignore[arg-type]
        userinfo_url=userinfo_url,  # type: ignore[arg-type]
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        scopes=scopes or [],
    )


def google(client_id: str, client_secret: str) -> OidcSettings:
    return oidc("https://accounts.google.com", client_id, client_secret)


def okta(domain: str, client_id: str, client_secret: str) -> OidcSettings:
    return oidc(f"https://{domain}", client_id, client_secret)


def auth0(domain: str, client_id: str, client_secret: str) -> OidcSettings:
    return oidc(f"https://{domain}", client_id, client_secret)


def entra(tenant_id: str, client_id: str, client_secret: str) -> OidcSettings:
    return oidc(
        f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        client_id,
        client_secret,
    )


def gitlab(
    client_id: str, client_secret: str, base_url: str = "https://gitlab.com"
) -> OidcSettings:
    return oidc(base_url, client_id, client_secret)


def github(client_id: str, client_secret: str) -> OAuth2Settings:
    return oauth2(
        authorize_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        userinfo_url="https://api.github.com/user",
        client_id=client_id,
        client_secret=client_secret,
        scopes=["read:user", "user:email"],
    )


def dev_idp(issuer: str, client_id: str, client_secret: str) -> OidcSettings:
    return oidc(issuer, client_id, client_secret)
