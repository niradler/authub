from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

import httpx
from starlette.requests import Request

from authub.errors import UnknownProtocolError
from authub.models import Connection, RawIdentity
from authub.state import BeginResult, FlowState


class HttpOptions:
    def __init__(self) -> None:
        self.transport: httpx.AsyncBaseTransport | None = None
        self.timeout: float = 10.0

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport, timeout=self.timeout)


class AuthProtocol(ABC):
    kind: ClassVar[str]

    @abstractmethod
    async def begin(
        self,
        *,
        conn: Connection,
        callback_url: str,
        return_to: str,
    ) -> BeginResult: ...

    @abstractmethod
    async def complete(
        self,
        *,
        request: Request,
        conn: Connection,
        callback_url: str,
        flow_state: FlowState,
    ) -> RawIdentity: ...


class ProtocolRegistry:
    def __init__(self) -> None:
        self._protocols: dict[str, AuthProtocol] = {}

    def register(self, protocol: AuthProtocol) -> None:
        self._protocols[protocol.kind] = protocol

    def get(self, kind: str) -> AuthProtocol:
        try:
            return self._protocols[kind]
        except KeyError as exc:
            raise UnknownProtocolError(f"No protocol registered for kind {kind!r}") from exc
