from __future__ import annotations

from authub import presets
from authub.models import OAuth2Settings, OidcSettings


def test_google() -> None:
    s = presets.google("cid", "cs")
    assert isinstance(s, OidcSettings)
    assert str(s.issuer).rstrip("/") == "https://accounts.google.com"
    assert "openid" in s.scopes


def test_okta_and_auth0_and_entra() -> None:
    assert (
        str(presets.okta("acme.okta.com", "c", "s").issuer).rstrip("/") == "https://acme.okta.com"
    )
    assert (
        str(presets.auth0("acme.auth0.com", "c", "s").issuer).rstrip("/")
        == "https://acme.auth0.com"
    )
    assert "tenant-1/v2.0" in str(presets.entra("tenant-1", "c", "s").issuer)


def test_github_is_oauth2_with_userinfo() -> None:
    s = presets.github("cid", "cs")
    assert isinstance(s, OAuth2Settings)
    assert str(s.userinfo_url) == "https://api.github.com/user"
    assert presets.GITHUB_MAPPING.external_id == "id"


def test_dev_idp_preset() -> None:
    s = presets.dev_idp("http://testserver/idp", "cid", "cs")
    assert isinstance(s, OidcSettings)
    assert str(s.issuer).rstrip("/") == "http://testserver/idp"


def test_secret_not_leaked_in_repr() -> None:
    assert "supersecret" not in repr(presets.google("cid", "supersecret"))
