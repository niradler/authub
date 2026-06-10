from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

import httpx
from starlette.requests import Request

from authub.errors import UnknownProtocolError
from authub.models import IdentityProvider, RawIdentity
from authub.state import BeginResult, FlowState


class HttpOptions:
    """Shared httpx configuration injected into protocol implementations.

    Set ``transport`` to an ``httpx.MockTransport`` or ``ASGITransport`` in tests to avoid
    real network calls.
    """

    def __init__(self) -> None:
        self.transport: httpx.AsyncBaseTransport | None = None
        self.timeout: float = 10.0

    def client(self) -> httpx.AsyncClient:
        """Return a configured ``AsyncClient`` using the current transport and timeout."""
        return httpx.AsyncClient(transport=self.transport, timeout=self.timeout)


class AuthProtocol(ABC):
    """Abstract base for an authentication protocol (OIDC, OAuth2, SAML, …).

    Each concrete subclass handles one ``kind`` and is registered with ``ProtocolRegistry``.
    The two-step flow is:

    1. ``begin`` — redirect the user to the IdP and return ``BeginResult`` containing the
       redirect URL and a ``FlowState`` that must be persisted (cookie) between steps.
    2. ``complete`` — receive the IdP callback, validate it against the saved ``FlowState``,
       and return the raw identity claims as ``RawIdentity``.

    Both steps raise ``ProtocolError`` on IdP errors, ``InvalidStateError`` on CSRF/state
    mismatches, and ``ConfigurationError`` for unrecoverable setup problems.
    """

    kind: ClassVar[str]

    @abstractmethod
    async def begin(
        self,
        *,
        idp: IdentityProvider,
        callback_url: str,
        return_to: str,
    ) -> BeginResult:
        """Start the login flow. Return the IdP redirect URL and per-request state."""
        ...

    @abstractmethod
    async def complete(
        self,
        *,
        request: Request,
        idp: IdentityProvider,
        callback_url: str,
        flow_state: FlowState,
    ) -> RawIdentity:
        """Finish the login flow. Validate the callback and return unmapped IdP claims."""
        ...


class ProtocolRegistry:
    """Registry mapping ``kind`` strings to ``AuthProtocol`` instances."""

    def __init__(self) -> None:
        self._protocols: dict[str, AuthProtocol] = {}

    def register(self, protocol: AuthProtocol) -> None:
        """Add or replace the protocol handler for ``protocol.kind``."""
        self._protocols[protocol.kind] = protocol

    def get(self, kind: str) -> AuthProtocol:
        """Return the handler for ``kind``. Raise ``UnknownProtocolError`` when not registered."""
        try:
            return self._protocols[kind]
        except KeyError as exc:
            raise UnknownProtocolError(f"No protocol registered for kind {kind!r}") from exc
