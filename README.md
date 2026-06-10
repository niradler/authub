# authub

A typed, composable authentication hub for [FastAPI](https://fastapi.tiangolo.com/) — wire OAuth2, OIDC, and SAML single sign-on into your app with a single object, issue your own user and service JWTs, and plug in your own stores, email senders, and identity-mapping logic. It even ships with an embedded OIDC identity provider so you can run the whole loop locally.

[![PyPI version](https://img.shields.io/pypi/v/authub.svg)](https://pypi.org/project/authub/)
[![Python versions](https://img.shields.io/pypi/pyversions/authub.svg)](https://pypi.org/project/authub/)
[![CI](https://github.com/niradler/authub/actions/workflows/ci.yml/badge.svg)](https://github.com/niradler/authub/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Typed](https://img.shields.io/badge/typed-mypy%20strict-blue.svg)](https://mypy-lang.org/)

> [!NOTE]
> authub is in active development (alpha). The API is stabilizing but may change before 1.0. Pin a version in production.

## Why authub

Most apps end up gluing together one OAuth client library, one SAML toolkit, a JWT signer, and a pile of provider-specific quirks. authub gives you a single, fully typed seam over all of it:

- **One object to wire** — construct `Authub(...)`, call `attach(app)`, and login/callback/logout/discovery routes appear under `/auth`.
- **Protocol-agnostic** — OAuth2, OIDC, and SAML providers behave identically once configured. Every raw identity is normalized into one canonical shape.
- **Bring your own everything** — user store, identity-provider store, revocation store, email sender, and claim mapper are all injectable protocols with sensible in-memory defaults.
- **Typed end to end** — Pydantic v2 on every boundary, `mypy --strict` clean, `SecretStr` for every secret.

## Features

- **OAuth2 and OIDC SP** — Google, GitHub, Okta, Auth0, Entra ID, GitLab, and any standards-compliant provider, with one-line presets.
- **SAML 2.0 SP** — assertion verification via `xmlsec` (optional extra).
- **User and service JWTs** — pluggable signing (HS256 or Ed25519), with FastAPI dependencies for route protection.
- **Embedded OIDC IdP** — `authub.idp.AuthubIdp`: authorization code + PKCE, RS256 ID tokens, refresh tokens with rotation, optional consent screen, and `/userinfo`.
- **SCIM 2.0 provisioning** — `authub.scim.ScimServer`: inbound Users and Groups with multi-tenant token isolation.
- **Plugin hooks** — normalize identities, provision users, and shape token claims without subclassing the core.

## Installation

```sh
pip install authub
```

With SAML support (requires the `xmlsec1` system library):

```sh
pip install "authub[saml]"
```

All extras:

```sh
pip install "authub[all]"
```

## Quick start

```python
from fastapi import Depends, FastAPI

from authub import Authub, IdentityProvider, Principal
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

auth = Authub(
    identity_providers=identity_providers,
    tokens=JwtTokenService.hs256(secret="change-me-to-a-32-char-secret!!"),
    state_secret="another-secret-at-least-32-chars",
)

app = FastAPI()
auth.attach(app)


@app.get("/me")
async def me(user: Principal = Depends(auth.current_user)) -> dict[str, str]:
    return {"id": user.id, "email": user.email or ""}
```

After `auth.attach(app)`, these routes are registered under `/auth`:

| Route | Purpose |
| --- | --- |
| `GET /auth/{idp_id}/login` | Start the OAuth2/OIDC/SAML flow |
| `GET\|POST /auth/{idp_id}/callback` | Receive the IdP callback (`POST` is the SAML ACS) |
| `GET /auth/discover` | List identity providers for an email address |
| `POST /auth/logout` | Revoke the current token (when a revocation store is configured) |

To verify a token programmatically: `claims = await auth.verify_token(token)`.

## Identity providers

An `IdentityProvider` binds a tenant to one IdP: it carries the protocol settings and an optional claim mapping.

```python
from authub import IdentityProvider
from authub.presets import oidc, oauth2

okta = IdentityProvider(
    id="okta",
    tenant_id="acme",
    display_name="Okta",
    settings=oidc(
        issuer="https://acme.okta.com",
        client_id="CLIENT_ID",
        client_secret="CLIENT_SECRET",
    ),
)

github = IdentityProvider(
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

### Preset helpers

`authub.presets` provides one-liner constructors for common providers:

```python
from authub.presets import google, github, okta, auth0, entra, gitlab, authub_idp
```

| Helper | Protocol | Notes |
| --- | --- | --- |
| `google(client_id, client_secret)` | OIDC | `accounts.google.com` |
| `github(client_id, client_secret)` | OAuth2 | `api.github.com/user` for userinfo |
| `okta(domain, client_id, client_secret)` | OIDC | `https://{domain}` |
| `auth0(domain, client_id, client_secret)` | OIDC | `https://{domain}` |
| `entra(tenant_id, client_id, client_secret)` | OIDC | Azure AD / Entra, v2.0 endpoint |
| `gitlab(client_id, client_secret, base_url)` | OIDC | default `gitlab.com` |
| `authub_idp(issuer, client_id, client_secret)` | OIDC | points at the embedded `AuthubIdp` |

## Protecting routes

`Authub` exposes ready-made FastAPI dependencies that resolve the bearer token to a `Principal`:

```python
from fastapi import Depends
from authub import Principal

@app.get("/profile")
async def profile(user: Principal = Depends(auth.current_user)):
    ...  # requires a valid user JWT

@app.get("/internal")
async def internal(p: Principal = Depends(auth.current_principal)):
    ...  # accepts any valid JWT (user or service)

@app.post("/admin")
async def admin(p: Principal = Depends(auth.require_roles("admin"))):
    ...  # principal must hold ANY of the given roles

@app.get("/billing")
async def billing(p: Principal = Depends(auth.require_scopes("billing:read"))):
    ...  # principal must hold ALL of the given scopes
```

## Token services

JWTs are issued and verified by a `TokenService`. The built-in `JwtTokenService` supports symmetric and asymmetric signing:

```python
from authub.tokens.jwt import JwtTokenService

# Symmetric — secret must be at least 32 characters
tokens = JwtTokenService.hs256(secret="change-me-to-a-32-char-secret!!")

# Asymmetric — generates an Ed25519 keypair when no PEM is supplied
tokens = JwtTokenService.ed25519()
public_pem = tokens.public_key_pem  # distribute to verify-only services

# Verify-only service (e.g. a downstream microservice)
verifier = JwtTokenService.ed25519_verifier(public_key_pem=public_pem)
```

Issue a service token for machine-to-machine calls:

```python
from authub import Principal, PrincipalType

svc = Principal(id="reporting-job", type=PrincipalType.SERVICE, tenant_id="acme")
token = await auth.issue_service_token(svc)  # pass ttl=None for a non-expiring token
```

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

- `on_identity(raw, idp)` — raw IdP claims, before normalization
- `on_user_provisioned(principal, identity)` — when a new user is created
- `before_issue_token(claims, principal, identity)` — mutate the JWT payload before signing
- `on_token_verify(claims)` — on every successful token verification

## Embedded OIDC IdP

`AuthubIdp` is a full OIDC provider — authorization code flow with PKCE, RS256 ID tokens, refresh tokens with rotation and reuse detection, an optional consent screen, and a `/userinfo` endpoint. Mount its router alongside your app.

> [!IMPORTANT]
> For production, configure it explicitly:
>
> - **Pass a persistent `signing_key`** (PEM-encoded RSA private key). Without it, an ephemeral key is generated on each startup, invalidating existing tokens and breaking multi-instance deployments.
> - **Provide a durable `IdpUserStore`** — `InMemoryIdpUserStore` loses users on restart.
> - **Provide a durable `IdpGrantStore`** for multi-instance deployments — the in-memory grant store is per-process and will cause cross-instance token failures.

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
    require_consent=True,  # show a consent screen before issuing a code
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

Refresh tokens are issued when the client requests the `offline_access` scope, and rotate on every use. Login throttling (`max_login_attempts`, `lockout_seconds`) is tracked per-instance in memory.

> [!NOTE]
> The IdP supports the authorization code flow (`response_type=code`) and refresh tokens. Implicit, device, and client-credentials flows are not implemented.

## SCIM 2.0 provisioning

`ScimServer` exposes an inbound SCIM 2.0 endpoint for Users and Groups, with multi-tenant isolation driven by a bearer-token authenticator.

```python
from fastapi import FastAPI

from authub.scim import ScimServer, StaticTokenAuthenticator

scim = ScimServer(
    authenticator=StaticTokenAuthenticator({"secret-token": "acme"}),  # token -> tenant_id
)

app = FastAPI()
scim.attach(app)  # mounts under /scim/v2
```

It implements `/Users` and `/Groups` (create, read, list with `eq` filters, replace, PATCH, delete) plus `/ServiceProviderConfig`, `/ResourceTypes`, and `/Schemas`. Bring a durable `ScimUserStore` / `ScimGroupStore` for production.

## SAML

Install `authub[saml]` and ensure `xmlsec1` is available on your system (via OS package managers; not available on Windows without WSL).

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

> [!NOTE]
> SAML tests are skipped on Windows (no `xmlsec1` binary). CI runs them on Ubuntu.

## Development

```sh
uv sync --dev --all-extras   # install dependencies
uv run pytest -q             # run the test suite
uv run ruff check .          # lint
uv run mypy                  # type-check (strict)
uv build                     # build wheel + sdist
```
