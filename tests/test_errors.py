from __future__ import annotations

from authub.errors import (
    AuthubError,
    ConnectionNotFoundError,
    InvalidStateError,
    InvalidTokenError,
    MappingError,
    ProtocolError,
    TokenRevokedError,
)


def test_error_defaults() -> None:
    err = ConnectionNotFoundError()
    assert err.code == "connection_not_found"
    assert err.status_code == 404
    assert isinstance(err, AuthubError)
    assert str(err) == err.detail


def test_error_custom_detail() -> None:
    err = ProtocolError("IdP said no")
    assert err.detail == "IdP said no"
    assert err.status_code == 400


def test_revoked_is_invalid_token() -> None:
    assert issubclass(TokenRevokedError, InvalidTokenError)
    assert TokenRevokedError().status_code == 401


def test_statuses() -> None:
    assert InvalidStateError().status_code == 400
    assert MappingError().status_code == 422
