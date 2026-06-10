from __future__ import annotations

import time

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import OctKey
from pydantic import BaseModel, SecretStr

from authub.errors import ConfigurationError, InvalidStateError

STATE_COOKIE = "__authub_state"
_STATE_TYP = "authub-state+jwt"


class FlowState(BaseModel):
    """Transient per-login state persisted in a short-lived HttpOnly cookie.

    Carries connection, PKCE, nonce, and return-to data between the login and callback steps.
    """

    connection_id: str
    return_to: str = "/"
    state: str | None = None
    nonce: str | None = None
    code_verifier: str | None = None
    request_id: str | None = None


class BeginResult(BaseModel):
    """Return value of ``AuthProtocol.begin``: the IdP redirect URL and the state to store."""

    redirect_url: str
    flow_state: FlowState


class FlowStateCodec:
    """Serialises and validates ``FlowState`` as a short-lived HS256-signed JWT cookie.

    The JWT is set as an HttpOnly cookie by the login route and consumed once during the callback.
    Decoding raises ``InvalidStateError`` if the token is expired, has the wrong type header,
    or cannot be parsed.

    Args:
        secret: Symmetric secret used for HS256 signing; must be at least 32 characters.
        ttl_seconds: Cookie lifetime in seconds (default 600 / 10 minutes).
    """

    def __init__(self, secret: str | SecretStr, ttl_seconds: int = 600) -> None:
        raw = secret.get_secret_value() if isinstance(secret, SecretStr) else secret
        if len(raw) < 32:
            raise ConfigurationError("state_secret must be at least 32 characters")
        self._key = OctKey.import_key(raw)
        self._ttl = ttl_seconds

    @property
    def ttl_seconds(self) -> int:
        """Configured lifetime in seconds for the state cookie."""
        return self._ttl

    def encode(self, flow_state: FlowState) -> str:
        """Serialize a ``FlowState`` to a signed JWT string."""
        now = int(time.time())
        claims: dict[str, object] = {
            "iat": now,
            "exp": now + self._ttl,
            "fs": flow_state.model_dump(mode="json"),
        }
        return jwt.encode(
            {"alg": "HS256", "typ": _STATE_TYP},
            claims,
            self._key,
            algorithms=["HS256"],
        )

    def decode(self, token: str) -> FlowState:
        """Parse and validate a JWT string back to a ``FlowState``.

        Raise ``InvalidStateError`` on any failure.
        """
        try:
            decoded = jwt.decode(token, self._key, algorithms=["HS256"])
        except JoseError as exc:
            raise InvalidStateError() from exc

        if decoded.header.get("typ") != _STATE_TYP:
            raise InvalidStateError()

        claims = decoded.claims
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)) or int(time.time()) > exp:
            raise InvalidStateError()

        raw_fs = claims.get("fs")
        if not isinstance(raw_fs, dict):
            raise InvalidStateError()

        try:
            return FlowState.model_validate(raw_fs)
        except Exception as exc:
            raise InvalidStateError() from exc
