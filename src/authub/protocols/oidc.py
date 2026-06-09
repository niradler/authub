from __future__ import annotations

import asyncio
import secrets
import time
from typing import Any, cast

from authlib.integrations.httpx_client import AsyncOAuth2Client
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from starlette.requests import Request

from authub.errors import InvalidStateError, ProtocolError
from authub.models import Connection, OidcSettings, RawIdentity
from authub.protocols.base import AuthProtocol, HttpOptions
from authub.state import BeginResult, FlowState

ID_TOKEN_ALGS = ["RS256", "RS384", "RS512", "PS256", "ES256", "ES384", "ES512", "Ed25519", "EdDSA"]


class OidcProtocol(AuthProtocol):
    kind = "oidc"

    def __init__(self, http: HttpOptions | None = None, metadata_ttl: int = 3600) -> None:
        self._http = http or HttpOptions()
        self._metadata_ttl = metadata_ttl
        self._metadata_cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._jwks_cache: dict[str, tuple[float, KeySet]] = {}
        self._cache_lock = asyncio.Lock()

    async def _discover(self, issuer: str) -> dict[str, Any]:
        issuer = issuer.rstrip("/")
        async with self._cache_lock:
            cached = self._metadata_cache.get(issuer)
            if cached and cached[0] > time.monotonic():
                return cached[1]
        url = f"{issuer}/.well-known/openid-configuration"
        async with self._http.client() as client:
            response = await client.get(url)
        if response.status_code != 200:
            raise ProtocolError("OIDC discovery failed")
        metadata = cast(dict[str, Any], response.json())
        if str(metadata.get("issuer", "")).rstrip("/") != issuer:
            raise ProtocolError("issuer mismatch in discovery document")
        async with self._cache_lock:
            self._metadata_cache[issuer] = (time.monotonic() + self._metadata_ttl, metadata)
        return metadata

    async def _keyset(self, metadata: dict[str, Any], force: bool = False) -> KeySet:
        jwks_uri = metadata.get("jwks_uri")
        if not isinstance(jwks_uri, str):
            raise ProtocolError("discovery document missing jwks_uri")
        async with self._cache_lock:
            cached = self._jwks_cache.get(jwks_uri)
            if cached and cached[0] > time.monotonic() and not force:
                return cached[1]
        async with self._http.client() as client:
            response = await client.get(jwks_uri)
        if response.status_code != 200:
            raise ProtocolError("JWKS fetch failed")
        keyset = KeySet.import_key_set(response.json())
        async with self._cache_lock:
            self._jwks_cache[jwks_uri] = (time.monotonic() + self._metadata_ttl, keyset)
        return keyset

    def _client(self, settings: OidcSettings, callback_url: str) -> AsyncOAuth2Client:
        return AsyncOAuth2Client(
            client_id=settings.client_id,
            client_secret=settings.client_secret.get_secret_value(),
            scope=" ".join(settings.scopes),
            redirect_uri=callback_url,
            code_challenge_method="S256",
            transport=self._http.transport,
            timeout=self._http.timeout,
        )

    async def begin(self, *, conn: Connection, callback_url: str, return_to: str) -> BeginResult:
        settings = cast(OidcSettings, conn.settings)
        metadata = await self._discover(str(settings.issuer))
        state = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        code_verifier = secrets.token_urlsafe(48)
        async with self._client(settings, callback_url) as client:
            url, _ = client.create_authorization_url(
                metadata["authorization_endpoint"],
                state=state,
                nonce=nonce,
                code_verifier=code_verifier,
            )
        return BeginResult(
            redirect_url=url,
            flow_state=FlowState(
                connection_id=conn.id,
                return_to=return_to,
                state=state,
                nonce=nonce,
                code_verifier=code_verifier,
            ),
        )

    async def complete(
        self,
        *,
        request: Request,
        conn: Connection,
        callback_url: str,
        flow_state: FlowState,
    ) -> RawIdentity:
        settings = cast(OidcSettings, conn.settings)
        params = request.query_params
        if "error" in params:
            raise ProtocolError(f"identity provider returned error: {params['error']}")
        code = params.get("code")
        if not code:
            raise ProtocolError("missing authorization code")
        if not flow_state.state or not secrets.compare_digest(
            params.get("state", ""), flow_state.state
        ):
            raise InvalidStateError("state parameter mismatch")

        metadata = await self._discover(str(settings.issuer))
        async with self._client(settings, callback_url) as client:
            try:
                token = await client.fetch_token(
                    metadata["token_endpoint"],
                    code=code,
                    code_verifier=flow_state.code_verifier,
                )
            except Exception as exc:
                raise ProtocolError("token exchange failed") from exc

        id_token = token.get("id_token")
        if not isinstance(id_token, str):
            raise ProtocolError("token response missing id_token")
        claims = await self._validate_id_token(id_token, metadata, settings, nonce=flow_state.nonce)

        if settings.fetch_userinfo and isinstance(metadata.get("userinfo_endpoint"), str):
            userinfo = await self._fetch_userinfo(
                metadata["userinfo_endpoint"], token["access_token"]
            )
            if userinfo.get("sub") != claims.get("sub"):
                raise ProtocolError("userinfo sub does not match id_token sub")
            claims = {**claims, **userinfo}
        return RawIdentity(claims=claims)

    async def _fetch_userinfo(self, endpoint: str, access_token: str) -> dict[str, Any]:
        async with self._http.client() as client:
            response = await client.get(
                endpoint,
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            )
        if response.status_code != 200:
            raise ProtocolError("userinfo fetch failed")
        return cast(dict[str, Any], response.json())

    async def _validate_id_token(
        self,
        raw_token: str,
        metadata: dict[str, Any],
        settings: OidcSettings,
        nonce: str | None,
    ) -> dict[str, Any]:
        keyset = await self._keyset(metadata)
        try:
            decoded = jwt.decode(raw_token, keyset, algorithms=ID_TOKEN_ALGS)
        except (JoseError, ValueError):
            keyset = await self._keyset(metadata, force=True)
            try:
                decoded = jwt.decode(raw_token, keyset, algorithms=ID_TOKEN_ALGS)
            except (JoseError, ValueError) as exc:
                raise ProtocolError("id_token signature validation failed") from exc

        registry = jwt.JWTClaimsRegistry(
            leeway=120,
            iss={"essential": True, "value": metadata["issuer"]},
            aud={"essential": True, "value": settings.client_id},
            exp={"essential": True},
            sub={"essential": True},
        )
        try:
            registry.validate(decoded.claims)
        except JoseError as exc:
            raise ProtocolError("id_token claims validation failed") from exc
        if nonce is not None and decoded.claims.get("nonce") != nonce:
            raise ProtocolError("nonce mismatch")
        return dict(decoded.claims)
