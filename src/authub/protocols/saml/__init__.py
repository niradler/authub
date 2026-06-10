from __future__ import annotations

import asyncio
from typing import Any, cast
from urllib.parse import urlencode

from starlette.requests import Request

from authub.errors import ConfigurationError, InvalidStateError, ProtocolError
from authub.models import IdentityProvider, RawIdentity, SamlSettings
from authub.protocols.base import AuthProtocol
from authub.protocols.saml._authn_request import build_authn_request
from authub.protocols.saml._idp_metadata import IdpInfo, parse_idp_metadata
from authub.protocols.saml._response import SamlResponseValidator
from authub.state import BeginResult, FlowState


class SamlProtocol(AuthProtocol):
    kind = "saml"

    def __init__(self, max_parallel: int = 4) -> None:
        self._semaphore = asyncio.Semaphore(max_parallel)

    @staticmethod
    def _acs_url(settings: SamlSettings, callback_url: str) -> str:
        return str(settings.acs_url) if settings.acs_url is not None else callback_url

    @staticmethod
    def _idp_info(settings: SamlSettings) -> IdpInfo:
        if settings.idp_metadata_xml is not None:
            xml = settings.idp_metadata_xml
        else:
            raise ConfigurationError(
                "idp_metadata_url is not supported at runtime without a metadata fetch — "
                "provide idp_metadata_xml instead, or pre-fetch and cache the XML"
            )
        try:
            return parse_idp_metadata(xml, entity_id=settings.idp_entity_id)
        except Exception as exc:
            raise ConfigurationError(f"Failed to parse IdP metadata: {exc}") from exc

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
        try:
            idp_info = self._idp_info(settings)
        except ConfigurationError:
            raise
        except Exception as exc:
            raise ProtocolError("Could not initialize SAML SP configuration") from exc

        try:
            request_id, encoded = build_authn_request(
                sp_entity_id=settings.sp_entity_id,
                acs_url=acs_url,
                sso_url=idp_info.sso_url,
                name_id_format=settings.name_id_format,
            )
        except Exception as exc:
            raise ProtocolError("Could not build SAML AuthnRequest") from exc

        params = urlencode({"SAMLRequest": encoded})
        redirect_url = f"{idp_info.sso_url}?{params}"
        return request_id, redirect_url

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
        self,
        settings: SamlSettings,
        acs_url: str,
        saml_response: str,
        request_id: str,
    ) -> dict[str, Any]:
        try:
            idp_info = self._idp_info(settings)
        except ConfigurationError:
            raise
        except Exception as exc:
            raise ProtocolError("Could not initialize SAML SP configuration") from exc

        validator = SamlResponseValidator(
            sp_entity_id=settings.sp_entity_id,
            idp_entity_id=idp_info.entity_id,
            acs_url=acs_url,
            cert_pem=idp_info.cert_pem,
            want_assertions_signed=settings.want_assertions_signed,
            want_response_signed=settings.want_response_signed,
        )
        try:
            return validator.parse_and_validate(saml_response, request_id)
        except Exception as exc:
            raise ProtocolError("SAML response validation failed") from exc
