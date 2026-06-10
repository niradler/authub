# authub

Typed, composable authentication hub for FastAPI.

## Features

- OAuth2 and OIDC SP (Google, GitHub, Okta, Auth0, Entra, GitLab, and any standard provider)
- SAML 2.0 SP (requires `pysaml2` and `xmlsec1`)
- User and service JWTs with pluggable signing (HS256, Ed25519)
- Pluggable stores (user store, identity provider store, revocation store) and email senders
- Plugin hooks for identity normalization, user provisioning, and token issuance
- Embedded OIDC IdP (`authub.idp.AuthubIdp`) — a production-grade OIDC provider with injectable signing keys and pluggable stores

## Installation

```sh
pip install authub
```

With SAML support:

```sh
pip install "authub[saml]"
```

All extras:

```sh
pip install "authub[all]"
```

## Quick start

```python
from fastapi import FastAPI

from authub import Authub, IdentityProvider
from authub.presets import oidc
from authub.stores.memory import InMemoryIdentityProviderStore
from authub.tokens.jwt import JwtTokenService

identity_providers = InMemoryIdentityProviderStore(
    identity_providers=[
        IdentityProvider(
            id="google",
            tenant_id="acme",
            display_name="Google",
            settings=oidc(
                issuer="https://accounts.google.com",
                client_id="YOUR_CLIENT_ID",
                client_secret="YOUR_CLIENT_SECRET",
            ),
        )
    ]
)

tokens = JwtTokenService.hs256(secret="change-me-to-a-32-char-secret!!")

auth = Authub(
    identity_providers=identity_providers,
    tokens=tokens,
    state_secret="another-secret-at-least-32-chars",
)

app = FastAPI()
auth.attach(app)
```

After `auth.attach(app)`, the following routes are registered under `/auth`:

- `GET /auth/{idp_id}/login` — start the OAuth2/OIDC/SAML flow
- `GET|POST /auth/{idp_id}/callback` — receive the IdP callback (POST is for SAML ACS)
- `GET /auth/discover` — list identity providers for an email address
- `POST /auth/logout` — revoke the current token (if revocation store configured)

To verify a token programmatically: `claims = await hub.verify_token(token)`

## Identity Providers

An `IdentityProvider` binds a tenant to one IdP: it carries the protocol settings and an optional claim mapping.

```python
from authub import IdentityProvider
from authub.presets import oidc, oauth2

oidc_idp = IdentityProvider(
    id="okta",
    tenant_id="acme",
    display_name="Okta",
    settings=oidc(
        issuer="https://acme.okta.com",
        client_id="CLIENT_ID",
        client_secret="CLIENT_SECRET",
    ),
)

github_idp = IdentityProvider(
    id="github",
    tenant_id="acme",
    display_name="GitHub",
    settings=oauth2(
        authorize_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        userinfo_url="https://api.github.com/user",
        client_id="CLIENT_ID",
        client_secret="CLIENT_SECRET",
        scopes=["read:user", "user:email"],
    ),
)
```

## Preset helpers

`authub.presets` provides one-liner constructors for common IdPs:

```python
from authub.presets import google, github, okta, auth0, entra, gitlab, authub_idp
```

| Helper | Protocol | Notes |
| --- | --- | --- |
| `google(client_id, client_secret)` | OIDC | `accounts.google.com` |
| `github(client_id, client_secret)` | OAuth2 | `api.github.com/user` for userinfo |
| `okta(domain, client_id, client_secret)` | OIDC | `https://{domain}` |
| `auth0(domain, client_id, client_secret)` | OIDC | `https://{domain}` |
| `entra(tenant_id, client_id, client_secret)` | OIDC | Azure AD / Entra |
| `gitlab(client_id, client_secret, base_url)` | OIDC | default `gitlab.com` |
| `authub_idp(issuer, client_id, client_secret)` | OIDC | points at the embedded AuthubIdp |

## Plugins

Subclass `Plugin` and pass instances to `Authub(plugins=[...])`. Override only the hooks you need:

```python
from typing import Any

from authub import Plugin
from authub.models import CanonicalIdentity, Principal


class TenantClaimPlugin(Plugin):
    async def before_issue_token(
        self,
        claims: dict[str, Any],
        principal: Principal,
        identity: CanonicalIdentity | None,
    ) -> dict[str, Any]:
        claims["tenant"] = principal.tenant_id
        return claims
```

Available hooks:

- `on_identity(raw, idp)` — called with raw IdP claims before normalization
- `on_user_provisioned(principal, identity)` — called when a new user is created
- `before_issue_token(claims, principal, identity)` — mutate JWT payload before signing
- `on_token_verify(claims)` — called on every successful token verification

## Embedded OIDC IdP

`AuthubIdp` is a full OIDC provider (authorization code + PKCE, RS256 ID tokens, `/userinfo`) that you can mount alongside your FastAPI app. It is suitable for production when configured correctly.

### Production checklist

- **Pass a persistent `signing_key`** — a PEM-encoded RSA private key. Without it, an ephemeral key is generated on each startup, invalidating existing tokens and breaking multi-instance deployments.
- **Provide a durable `IdpUserStore`** — `InMemoryIdpUserStore` loses users on restart.
- **Provide a durable `IdpGrantStore`** for multi-instance deployments — `InMemoryIdpGrantStore` is per-process and will cause cross-instance token failures.

### Current limitations

- Authorization code flow only (`response_type=code`); no implicit, device, or client-credentials flows.
- No refresh tokens.
- No consent screen.
- Login throttling (`max_login_attempts`, `lockout_seconds`) is tracked per-instance in memory.

### Example

```python
import os
from fastapi import FastAPI
from pydantic import SecretStr

from authub import Authub, IdentityProvider
from authub.idp import AuthubIdp, IdpClient, InMemoryIdpUserStore
from authub.presets import authub_idp
from authub.stores.memory import InMemoryIdentityProviderStore
from authub.tokens.jwt import JwtTokenService

IDP_ISSUER = "https://auth.example.com/idp"
CLIENT_ID = "myapp"
CLIENT_SECRET = "change-me"

idp_users = InMemoryIdpUserStore()
idp_users.add_user("alice", "password", email="alice@example.com", name="Alice")

idp = AuthubIdp(
    issuer=IDP_ISSUER,
    clients=[
        IdpClient(
            client_id=CLIENT_ID,
            client_secret=SecretStr(CLIENT_SECRET),
            redirect_uris=["https://app.example.com/auth/myidp/callback"],
        )
    ],
    users=idp_users,
    signing_key=os.environ["IDP_SIGNING_KEY_PEM"],
)

identity_providers = InMemoryIdentityProviderStore(
    identity_providers=[
        IdentityProvider(
            id="myidp",
            tenant_id="acme",
            display_name="authub IdP",
            settings=authub_idp(
                issuer=IDP_ISSUER,
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
            ),
        )
    ]
)

auth = Authub(
    identity_providers=identity_providers,
    tokens=JwtTokenService.hs256(secret="secret-must-be-32-chars-long!!!"),
    state_secret="state-secret-must-be-32-chars!!",
)

app = FastAPI()
app.include_router(idp.router, prefix="/idp")
auth.attach(app)
```

## SAML

Install `authub[saml]` and ensure `xmlsec1` is on your `PATH` (available via OS package managers; not available on Windows without WSL).

```python
from pydantic import AnyHttpUrl

from authub import IdentityProvider
from authub.models import SamlSettings

saml_idp = IdentityProvider(
    id="corp-saml",
    tenant_id="acme",
    display_name="Corporate SSO",
    settings=SamlSettings(
        sp_entity_id="https://app.example.com/auth/corp-saml/metadata",
        idp_metadata_url=AnyHttpUrl("https://idp.example.com/saml/metadata"),
        want_assertions_signed=True,
    ),
)
```

SAML tests are skipped on Windows (no `xmlsec1` binary). CI runs them on Ubuntu.

## License

MIT — see [LICENSE](LICENSE).
