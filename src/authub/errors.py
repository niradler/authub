"""Authub error hierarchy — all details are client-safe; log internals at the raise site."""

from __future__ import annotations


class AuthubError(Exception):
    code: str = "authub_error"
    status_code: int = 400
    default_detail: str = "Authentication error"

    def __init__(self, detail: str | None = None) -> None:
        self.detail = detail if detail is not None else self.default_detail
        super().__init__(self.detail)


class ConfigurationError(AuthubError):
    code = "configuration_error"
    status_code = 500
    default_detail = "Authub is misconfigured"


class ConnectionNotFoundError(AuthubError):
    code = "connection_not_found"
    status_code = 404
    default_detail = "Unknown connection"


class UnknownProtocolError(AuthubError):
    code = "unknown_protocol"
    status_code = 500
    default_detail = "No protocol registered for this connection"


class InvalidStateError(AuthubError):
    code = "invalid_state"
    status_code = 400
    default_detail = "Login state is missing, expired, or does not match"


class ProtocolError(AuthubError):
    code = "protocol_error"
    status_code = 400
    default_detail = "Identity provider response was rejected"


class MappingError(AuthubError):
    code = "mapping_error"
    status_code = 422
    default_detail = "Identity claims could not be mapped"


class InvalidTokenError(AuthubError):
    code = "invalid_token"
    status_code = 401
    default_detail = "Token is invalid or expired"


class TokenRevokedError(InvalidTokenError):
    code = "token_revoked"
    default_detail = "Token has been revoked"


class ForbiddenError(AuthubError):
    code = "forbidden"
    status_code = 403
    default_detail = "Not allowed"
