from __future__ import annotations

import secrets
from typing import Any, cast

from authlib.integrations.httpx_client import AsyncOAuth2Client
from starlette.requests import Request

from authub.errors import InvalidStateError, ProtocolError
from authub.models import Connection, OAuth2Settings, RawIdentity
from authub.protocols.base import AuthProtocol, HttpOptions
from authub.state import BeginResult, FlowState


class OAuth2Protocol(AuthProtocol):
    kind = "oauth2"

    def __init__(self, http: HttpOptions | None = None) -> None:
        self._http = http or HttpOptions()

    def _client(self, settings: OAuth2Settings, callback_url: str) -> AsyncOAuth2Client:
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
        settings = cast(OAuth2Settings, conn.settings)
        state = secrets.token_urlsafe(24)
        code_verifier = secrets.token_urlsafe(48)
        async with self._client(settings, callback_url) as client:
            url, _ = client.create_authorization_url(
                str(settings.authorize_url), state=state, code_verifier=code_verifier
            )
        return BeginResult(
            redirect_url=url,
            flow_state=FlowState(
                connection_id=conn.id,
                return_to=return_to,
                state=state,
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
        settings = cast(OAuth2Settings, conn.settings)
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

        async with self._client(settings, callback_url) as client:
            try:
                token = await client.fetch_token(
                    str(settings.token_url),
                    code=code,
                    code_verifier=flow_state.code_verifier,
                )
            except Exception as exc:
                raise ProtocolError("token exchange failed") from exc

        token_payload = dict(token)
        if settings.userinfo_url is not None:
            claims = await self._fetch_userinfo(
                str(settings.userinfo_url), token_payload.get("access_token", "")
            )
        else:
            claims = {k: v for k, v in token_payload.items() if k != "access_token"}
        claims["_oauth_token"] = token_payload
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
