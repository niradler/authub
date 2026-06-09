from __future__ import annotations

from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from authub.errors import AuthubError
from authub.web.deps import extract_token

if TYPE_CHECKING:
    from authub.hub import Authub


class PrincipalMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, hub: Authub) -> None:
        super().__init__(app)
        self._hub = hub

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request.state.principal = None
        pair = extract_token(request, self._hub)
        if pair is not None:
            try:
                claims = await self._hub.verify_token(pair[0])
                request.state.principal = claims.to_principal()
            except AuthubError:
                request.state.principal = None
        return await call_next(request)
