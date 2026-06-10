from __future__ import annotations

import asyncio
import shutil
from typing import Any, cast

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import SPConfig
from starlette.requests import Request

from authub.errors import ConfigurationError, InvalidStateError, ProtocolError
from authub.models import IdentityProvider, RawIdentity, SamlSettings
from authub.protocols.base import AuthProtocol
from authub.state import BeginResult, FlowState


class SamlProtocol(AuthProtocol):
    """SAML 2.0 SP protocol backed by pysaml2 with bounded parallelism via asyncio.Semaphore.

    Requires the ``xmlsec1`` binary on PATH (or passed via ``xmlsec_binary``).
    """

    kind = "saml"

    def __init__(self, max_parallel: int = 4, xmlsec_binary: str | None = None) -> None:
        self._semaphore = asyncio.Semaphore(max_parallel)
        self._xmlsec = xmlsec_binary or shutil.which("xmlsec1")

    def _sp_config(self, settings: SamlSettings, acs_url: str) -> SPConfig:
        if self._xmlsec is None:
            raise ConfigurationError(
                "SAML needs the xmlsec1 binary on PATH (debian: apt install xmlsec1)"
            )
        metadata: dict[str, Any]
        if settings.idp_metadata_xml is not None:
            metadata = {"inline": [settings.idp_metadata_xml]}
        else:
            metadata = {"remote": [{"url": str(settings.idp_metadata_url)}]}
        config: dict[str, Any] = {
            "entityid": settings.sp_entity_id,
            "metadata": metadata,
            "xmlsec_binary": self._xmlsec,
            "allow_unknown_attributes": True,
            "service": {
                "sp": {
                    "endpoints": {
                        "assertion_consumer_service": [(acs_url, BINDING_HTTP_POST)],
                    },
                    "want_assertions_signed": settings.want_assertions_signed,
                    "want_response_signed": settings.want_response_signed,
                    "allow_unsolicited": False,
                    "authn_requests_signed": False,
                    "name_id_format": settings.name_id_format,
                },
            },
        }
        sp_config = SPConfig()
        sp_config.load(config)
        return sp_config

    @staticmethod
    def _acs_url(settings: SamlSettings, callback_url: str) -> str:
        return str(settings.acs_url) if settings.acs_url is not None else callback_url

    async def begin(
        self, *, idp: IdentityProvider, callback_url: str, return_to: str
    ) -> BeginResult:
        settings = cast(SamlSettings, idp.settings)
        acs_url = self._acs_url(settings, callback_url)
        async with self._semaphore:
            request_id, redirect_url = await asyncio.to_thread(self._begin_sync, settings, acs_url)
        return BeginResult(
            redirect_url=redirect_url,
            flow_state=FlowState(idp_id=idp.id, return_to=return_to, request_id=request_id),
        )

    def _begin_sync(self, settings: SamlSettings, acs_url: str) -> tuple[str, str]:
        client = Saml2Client(self._sp_config(settings, acs_url))
        idp_entity_id = settings.idp_entity_id
        if idp_entity_id is None:
            candidates = list(client.metadata.identity_providers())
            if len(candidates) != 1:
                raise ProtocolError("set idp_entity_id: metadata does not contain exactly one IdP")
            idp_entity_id = candidates[0]
        try:
            request_id, http_info = client.prepare_for_authenticate(
                entityid=idp_entity_id,
                binding=BINDING_HTTP_REDIRECT,
                response_binding=BINDING_HTTP_POST,
            )
        except Exception as exc:
            raise ProtocolError("could not build SAML AuthnRequest") from exc
        headers = dict(http_info.get("headers") or [])
        redirect_url = headers.get("Location") or http_info.get("url")
        if not redirect_url:
            raise ProtocolError("pysaml2 returned no redirect target")
        return str(request_id), str(redirect_url)

    async def complete(
        self,
        *,
        request: Request,
        idp: IdentityProvider,
        callback_url: str,
        flow_state: FlowState,
    ) -> RawIdentity:
        settings = cast(SamlSettings, idp.settings)
        if not flow_state.request_id:
            raise InvalidStateError("missing SAML request id in login state")
        form = await request.form()
        saml_response = form.get("SAMLResponse")
        if not isinstance(saml_response, str) or not saml_response:
            raise ProtocolError("missing SAMLResponse form field")
        acs_url = self._acs_url(settings, callback_url)
        async with self._semaphore:
            claims = await asyncio.to_thread(
                self._complete_sync, settings, acs_url, saml_response, flow_state.request_id
            )
        return RawIdentity(claims=claims)

    def _complete_sync(
        self, settings: SamlSettings, acs_url: str, saml_response: str, request_id: str
    ) -> dict[str, Any]:
        client = Saml2Client(self._sp_config(settings, acs_url))
        try:
            response = client.parse_authn_request_response(
                saml_response, BINDING_HTTP_POST, outstanding={request_id: "/"}
            )
        except Exception as exc:
            raise ProtocolError("SAML response validation failed") from exc
        if response is None:
            raise ProtocolError("SAML response could not be parsed")
        claims: dict[str, Any] = dict(response.get_identity())
        name_id = response.name_id
        claims["name_id"] = str(name_id.text) if name_id is not None else None
        claims["name_id_format"] = (
            str(name_id.format) if name_id is not None and name_id.format else None
        )
        claims["issuer"] = response.issuer()
        return claims
