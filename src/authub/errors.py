"""Authub error hierarchy — all details are client-safe; log internals at the raise site."""

from __future__ import annotations


class AuthubError(Exception):
    """Base class for all authub errors. Carries a client-safe ``detail`` string and HTTP status."""

    code: str = "authub_error"
    status_code: int = 400
    default_detail: str = "Authentication error"

    def __init__(self, detail: str | None = None) -> None:
        self.detail = detail if detail is not None else self.default_detail
        super().__init__(self.detail)


class ConfigurationError(AuthubError):
    """Raised at startup when required settings are missing or invalid. HTTP 500."""

    code = "configuration_error"
    status_code = 500
    default_detail = "Authub is misconfigured"


class IdentityProviderNotFoundError(AuthubError):
    """Raised when an identity provider ID does not exist in the store. HTTP 404."""

    code = "identity_provider_not_found"
    status_code = 404
    default_detail = "Unknown identity provider"


class UnknownProtocolError(AuthubError):
    """Raised when an identity provider references a protocol kind with no registered handler.

    HTTP 500.
    """

    code = "unknown_protocol"
    status_code = 500
    default_detail = "No protocol registered for this identity provider"


class InvalidStateError(AuthubError):
    """Raised when the login-flow state cookie is missing, expired, tampered with, or mismatched.

    HTTP 400.
    """

    code = "invalid_state"
    status_code = 400
    default_detail = "Login state is missing, expired, or does not match"


class ProtocolError(AuthubError):
    """Raised when the identity provider returns an error or an invalid response. HTTP 400."""

    code = "protocol_error"
    status_code = 400
    default_detail = "Identity provider response was rejected"


class MappingError(AuthubError):
    """Raised when IdP claims cannot be mapped to a ``CanonicalIdentity``.

    Triggered by a missing required claim, an unknown transform, or failed Pydantic validation.
    HTTP 422.
    """

    code = "mapping_error"
    status_code = 422
    default_detail = "Identity claims could not be mapped"


class InvalidTokenError(AuthubError):
    """Raised when a JWT fails signature or claims validation. HTTP 401."""

    code = "invalid_token"
    status_code = 401
    default_detail = "Token is invalid or expired"


class TokenRevokedError(InvalidTokenError):
    """Raised when a valid JWT has been explicitly revoked. Subclass of ``InvalidTokenError``.

    HTTP 401.
    """

    code = "token_revoked"
    default_detail = "Token has been revoked"


class ForbiddenError(AuthubError):
    """Raised when a principal is authenticated but lacks permission for the requested action.

    HTTP 403.
    """

    code = "forbidden"
    status_code = 403
    default_detail = "Not allowed"
