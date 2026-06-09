# authub

Typed, composable authentication hub for FastAPI.

## Features

- OAuth2 and OIDC SP (Google, GitHub, Okta, Auth0, Entra, GitLab, and any standard provider)
- SAML 2.0 SP (requires `pysaml2` and `xmlsec1`)
- User and service JWTs with pluggable signing (HS256, Ed25519)
- Pluggable stores (user store, connection store, revocation store) and email senders
- Plugin hooks for identity normalization, user provisioning, and token issuance
- Embedded dev OIDC IdP (`authub.idp.AuthubIdp`) for local development without a real IdP

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

from authub import Authub, Connection
from authub.presets import oidc
from authub.stores.memory import InMemoryConnectionStore
from authub.tokens.jwt import JwtTokenService

connections = InMemoryConnectionStore(
    connections=[
        Connection(
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
    connections=connections,
    tokens=tokens,
    state_secret="another-secret-at-least-32-chars",
)

app = FastAPI()
auth.attach(app)
```

After `auth.attach(app)`, the following routes are registered under `/auth`:

- `GET /auth/{connection_id}/login` — start the OAuth2/OIDC/SAML flow
- `GET /auth/{connection_id}/callback` — receive the IdP callback
- `POST /auth/token/verify` — verify and inspect a token
- `POST /auth/logout` — revoke the current token (if revocation store configured)

## Connections

A `Connection` binds a tenant to one IdP: it carries the protocol settings and an optional claim mapping.

```python
from authub import Connection
from authub.presets import oidc, oauth2

oidc_conn = Connection(
    id="okta",
    tenant_id="acme",
    display_name="Okta",
    settings=oidc(
        issuer="https://acme.okta.com",
        client_id="CLIENT_ID",
        client_secret="CLIENT_SECRET",
    ),
)

github_conn = Connection(
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
from authub.presets import google, github, okta, auth0, entra, gitlab, dev_idp
```

| Helper | Protocol | Notes |
| --- | --- | --- |
| `google(client_id, client_secret)` | OIDC | `accounts.google.com` |
| `github(client_id, client_secret)` | OAuth2 | `api.github.com/user` for userinfo |
| `okta(domain, client_id, client_secret)` | OIDC | `https://{domain}` |
| `auth0(domain, client_id, client_secret)` | OIDC | `https://{domain}` |
| `entra(tenant_id, client_id, client_secret)` | OIDC | Azure AD / Entra |
| `gitlab(client_id, client_secret, base_url)` | OIDC | default `gitlab.com` |
| `dev_idp(issuer, client_id, client_secret)` | OIDC | points at the embedded dev IdP |

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

- `on_identity(raw, conn)` — called with raw IdP claims before normalization
- `on_user_provisioned(principal, identity)` — called when a new user is created
- `before_issue_token(claims, principal, identity)` — mutate JWT payload before signing
- `on_token_verify(claims)` — called on every successful token verification

## Dev OIDC IdP

`AuthubIdp` is a fully functional OIDC provider for local development. Mount it alongside your app so you can test the full login flow without a real IdP.

```python
from fastapi import FastAPI
from pydantic import SecretStr

from authub import Authub, Connection
from authub.idp import AuthubIdp, IdpClient, InMemoryIdpUserStore
from authub.presets import dev_idp
from authub.stores.memory import InMemoryConnectionStore
from authub.tokens.jwt import JwtTokenService

IDP_ISSUER = "http://localhost:8000/idp"
CLIENT_ID = "dev-client"
CLIENT_SECRET = "dev-secret"

idp_users = InMemoryIdpUserStore()
idp_users.add_user(
    "alice",
    "password",
    email="alice@example.com",
    name="Alice Dev",
)

idp = AuthubIdp(
    issuer=IDP_ISSUER,
    clients=[
        IdpClient(
            client_id=CLIENT_ID,
            client_secret=SecretStr(CLIENT_SECRET),
            redirect_uris=["http://localhost:8000/auth/dev/callback"],
        )
    ],
    users=idp_users,
)

connections = InMemoryConnectionStore(
    connections=[
        Connection(
            id="dev",
            tenant_id="local",
            display_name="Dev IdP",
            settings=dev_idp(
                issuer=IDP_ISSUER,
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
            ),
        )
    ]
)

auth = Authub(
    connections=connections,
    tokens=JwtTokenService.hs256(secret="dev-secret-must-be-32-chars-long!"),
    state_secret="state-secret-must-be-32-chars!!",
)

app = FastAPI()
app.include_router(idp.router, prefix="/idp")
auth.attach(app)
```

`AuthubIdp` is for local development only. Do not expose it in production.

## SAML

Install `authub[saml]` and ensure `xmlsec1` is on your `PATH` (available via OS package managers; not available on Windows without WSL).

```python
from authub import Connection
from authub.models import SamlSettings

saml_conn = Connection(
    id="corp-saml",
    tenant_id="acme",
    display_name="Corporate SSO",
    settings=SamlSettings(
        sp_entity_id="https://app.example.com/auth/corp-saml/metadata",
        idp_metadata_url="https://idp.example.com/saml/metadata",  # type: ignore[arg-type]
        want_assertions_signed=True,
    ),
)
```

SAML tests are skipped on Windows (no `xmlsec1` binary). CI runs them on Ubuntu.

## License

MIT — see [LICENSE](LICENSE).
