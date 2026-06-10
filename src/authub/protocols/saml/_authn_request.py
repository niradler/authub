from __future__ import annotations

import base64
import zlib
from datetime import UTC, datetime
from hashlib import sha1
from uuid import uuid4

from authub.protocols.saml._constants import BINDING_HTTP_POST


def _generate_id() -> str:
    return "AUTHUB_" + sha1(uuid4().bytes).hexdigest()


def _now_saml() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_authn_request(
    *,
    sp_entity_id: str,
    acs_url: str,
    sso_url: str,
    name_id_format: str,
) -> tuple[str, str]:
    request_id = _generate_id()
    issue_instant = _now_saml()

    xml = (
        f"<samlp:AuthnRequest"
        f' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        f' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
        f' ID="{request_id}"'
        f' Version="2.0"'
        f' IssueInstant="{issue_instant}"'
        f' Destination="{sso_url}"'
        f' ProtocolBinding="{BINDING_HTTP_POST}"'
        f' AssertionConsumerServiceURL="{acs_url}">'
        f"<saml:Issuer>{sp_entity_id}</saml:Issuer>"
        f'<samlp:NameIDPolicy Format="{name_id_format}" AllowCreate="true" />'
        f"</samlp:AuthnRequest>"
    )

    compressed = zlib.compress(xml.encode())[2:-4]
    encoded = base64.b64encode(compressed).decode()
    return request_id, encoded
