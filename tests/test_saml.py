from __future__ import annotations

import base64
import datetime
import re
import zlib
from hashlib import sha1 as _sha1
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import uuid4

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from starlette.requests import Request

from authub import Authub, IdentityProvider, Mapping
from authub.errors import ProtocolError
from authub.models import SamlSettings
from authub.protocols.saml import SamlProtocol
from authub.protocols.saml._constants import RSA_SHA256, SHA256
from authub.protocols.saml._xmlsec import add_sign
from authub.state import STATE_COOKIE
from authub.stores.memory import InMemoryIdentityProviderStore
from authub.tokens.jwt import JwtTokenService

SP_ENTITY = "https://app.test/saml/metadata"
IDP_ENTITY = "https://idp.example.test/metadata"
ACS_URL = "http://testserver/auth/acme-saml/callback"

NAMEID_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
CM_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"


def _saml_ts(dt: datetime.datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_self_signed_cert(tmp_path: Path) -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "authub-test-idp")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return key_pem, cert_pem


def _cert_b64(cert_pem: bytes) -> str:
    raw = cert_pem.decode()
    raw = raw.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "")
    return raw.replace("\n", "").strip()


def make_idp_metadata(cert_pem: bytes) -> str:
    cert_b64 = _cert_b64(cert_pem)
    return f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{IDP_ENTITY}">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>{cert_b64}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>{NAMEID_PERSISTENT}</md:NameIDFormat>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://idp.example.test/sso" />
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""


def build_saml_response(
    *,
    request_id: str,
    key_pem: bytes,
    cert_pem: bytes,
    name_id: str = "ada-persistent-id",
    audience: str = SP_ENTITY,
    destination: str = ACS_URL,
    issuer: str = IDP_ENTITY,
    sign: bool = True,
    not_before_offset: int = -60,
    not_after_offset: int = 600,
    sc_in_response_to: str | None = None,
    include_audience: bool = True,
    sign_algorithm: str | None = None,
    digest_algorithm: str | None = None,
) -> str:
    now = datetime.datetime.now(datetime.UTC)
    issue_instant = _saml_ts(now)
    not_before = _saml_ts(now + datetime.timedelta(seconds=not_before_offset))
    not_after = _saml_ts(now + datetime.timedelta(seconds=not_after_offset))

    response_id = "R_" + _sha1(uuid4().bytes).hexdigest()
    assertion_id = "A_" + _sha1(uuid4().bytes).hexdigest()

    effective_irt = request_id if sc_in_response_to is None else sc_in_response_to
    irt_attr = f'InResponseTo="{effective_irt}"' if effective_irt != "" else ""

    attributes_xml = """
      <saml:AttributeStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
          <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:type="xs:string">ada@acme.example</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="cn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
          <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:type="xs:string">Ada</saml:AttributeValue>
        </saml:Attribute>
      </saml:AttributeStatement>"""

    audience_xml = (
        f"""<saml:AudienceRestriction>
      <saml:Audience>{audience}</saml:Audience>
    </saml:AudienceRestriction>"""
        if include_audience
        else ""
    )

    assertion_xml = f"""<saml:Assertion
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:xs="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    Version="2.0"
    ID="{assertion_id}"
    IssueInstant="{issue_instant}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="{NAMEID_PERSISTENT}">{name_id}</saml:NameID>
    <saml:SubjectConfirmation Method="{CM_BEARER}">
      <saml:SubjectConfirmationData
          NotOnOrAfter="{not_after}"
          {irt_attr}
          Recipient="{destination}" />
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_after}">
    {audience_xml}
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="{issue_instant}" SessionIndex="_session1">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
  {attributes_xml}
</saml:Assertion>"""

    if sign:
        eff_sign = sign_algorithm if sign_algorithm is not None else RSA_SHA256
        eff_digest = digest_algorithm if digest_algorithm is not None else SHA256
        signed_assertion_bytes = add_sign(
            assertion_xml.encode(), key_pem, cert_pem, eff_sign, eff_digest
        )
        signed_assertion = signed_assertion_bytes.decode()
    else:
        signed_assertion = assertion_xml

    response_xml = f"""<samlp:Response
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="{response_id}"
  InResponseTo="{request_id}"
  Version="2.0"
  IssueInstant="{issue_instant}"
  Destination="{destination}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="{STATUS_SUCCESS}" />
  </samlp:Status>
  {signed_assertion}
</samlp:Response>"""

    return base64.b64encode(response_xml.encode()).decode()


def post_request(path: str, data: dict[str, str]) -> Any:
    body = urlencode(data).encode()

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "http",
            "server": ("testserver", 80),
            "path": path,
            "query_string": b"",
            "headers": [
                (b"content-type", b"application/x-www-form-urlencoded"),
                (b"content-length", str(len(body)).encode()),
            ],
        },
        receive,
    )


def extract_request_id(redirect_url: str) -> str:
    qs = parse_qs(urlsplit(redirect_url).query)
    encoded = qs["SAMLRequest"][0]
    decoded = base64.b64decode(encoded)
    xml = zlib.decompress(decoded, -15).decode()
    m = re.search(r'ID="([^"]+)"', xml)
    assert m, f"No ID found in AuthnRequest: {xml[:200]}"
    return m.group(1)


@pytest.fixture
def idp_keys(tmp_path: Path) -> tuple[bytes, bytes]:
    return make_self_signed_cert(tmp_path)


@pytest.fixture
def saml_settings(idp_keys: tuple[bytes, bytes]) -> SamlSettings:
    _, cert_pem = idp_keys
    return SamlSettings(
        sp_entity_id=SP_ENTITY,
        idp_metadata_xml=make_idp_metadata(cert_pem),
        idp_entity_id=IDP_ENTITY,
    )


def make_conn(settings: SamlSettings) -> IdentityProvider:
    return IdentityProvider(
        id="acme-saml", tenant_id="acme", display_name="Acme SAML", settings=settings
    )


async def test_full_saml_round_trip(
    idp_keys: tuple[bytes, bytes], saml_settings: SamlSettings
) -> None:
    key_pem, cert_pem = idp_keys
    protocol = SamlProtocol()
    conn = make_conn(saml_settings)
    begin = await protocol.begin(idp=conn, callback_url=ACS_URL, return_to="/")
    assert "SAMLRequest=" in begin.redirect_url
    assert begin.flow_state.request_id

    request_id = extract_request_id(begin.redirect_url)
    assert request_id == begin.flow_state.request_id

    saml_response = build_saml_response(request_id=request_id, key_pem=key_pem, cert_pem=cert_pem)
    raw = await protocol.complete(
        request=post_request("/cb", {"SAMLResponse": saml_response, "RelayState": "/"}),
        idp=conn,
        callback_url=ACS_URL,
        flow_state=begin.flow_state,
    )
    assert raw.claims["mail"] == ["ada@acme.example"]
    assert raw.claims["name_id"] == "ada-persistent-id"
    assert raw.claims["issuer"] == IDP_ENTITY


async def test_unsigned_response_rejected(
    idp_keys: tuple[bytes, bytes], saml_settings: SamlSettings
) -> None:
    key_pem, cert_pem = idp_keys
    protocol = SamlProtocol()
    conn = make_conn(saml_settings)
    begin = await protocol.begin(idp=conn, callback_url=ACS_URL, return_to="/")
    request_id = extract_request_id(begin.redirect_url)

    saml_response = build_saml_response(
        request_id=request_id, key_pem=key_pem, cert_pem=cert_pem, sign=False
    )
    with pytest.raises(ProtocolError):
        await protocol.complete(
            request=post_request("/cb", {"SAMLResponse": saml_response}),
            idp=conn,
            callback_url=ACS_URL,
            flow_state=begin.flow_state,
        )


async def test_unknown_in_response_to_rejected(
    idp_keys: tuple[bytes, bytes], saml_settings: SamlSettings
) -> None:
    key_pem, cert_pem = idp_keys
    protocol = SamlProtocol()
    conn = make_conn(saml_settings)
    begin = await protocol.begin(idp=conn, callback_url=ACS_URL, return_to="/")
    request_id = extract_request_id(begin.redirect_url)

    saml_response = build_saml_response(request_id=request_id, key_pem=key_pem, cert_pem=cert_pem)
    forged_state = begin.flow_state.model_copy(update={"request_id": "id-forged"})
    with pytest.raises(ProtocolError):
        await protocol.complete(
            request=post_request("/cb", {"SAMLResponse": saml_response}),
            idp=conn,
            callback_url=ACS_URL,
            flow_state=forged_state,
        )


async def test_audience_mismatch_rejected(
    idp_keys: tuple[bytes, bytes], saml_settings: SamlSettings
) -> None:
    key_pem, cert_pem = idp_keys
    protocol = SamlProtocol()
    conn = make_conn(saml_settings)
    begin = await protocol.begin(idp=conn, callback_url=ACS_URL, return_to="/")
    request_id = extract_request_id(begin.redirect_url)

    saml_response = build_saml_response(
        request_id=request_id,
        key_pem=key_pem,
        cert_pem=cert_pem,
        audience="https://wrong.entity.test/sp",
    )
    with pytest.raises(ProtocolError):
        await protocol.complete(
            request=post_request("/cb", {"SAMLResponse": saml_response}),
            idp=conn,
            callback_url=ACS_URL,
            flow_state=begin.flow_state,
        )


async def test_expired_conditions_rejected(
    idp_keys: tuple[bytes, bytes], saml_settings: SamlSettings
) -> None:
    key_pem, cert_pem = idp_keys
    protocol = SamlProtocol()
    conn = make_conn(saml_settings)
    begin = await protocol.begin(idp=conn, callback_url=ACS_URL, return_to="/")
    request_id = extract_request_id(begin.redirect_url)

    saml_response = build_saml_response(
        request_id=request_id,
        key_pem=key_pem,
        cert_pem=cert_pem,
        not_before_offset=-3600,
        not_after_offset=-60,
    )
    with pytest.raises(ProtocolError):
        await protocol.complete(
            request=post_request("/cb", {"SAMLResponse": saml_response}),
            idp=conn,
            callback_url=ACS_URL,
            flow_state=begin.flow_state,
        )


async def test_saml_login_through_http_router(
    idp_keys: tuple[bytes, bytes], saml_settings: SamlSettings
) -> None:
    key_pem, cert_pem = idp_keys
    saml_mapping = Mapping(external_id="name_id", email="mail", name="cn")
    connection = IdentityProvider(
        id="acme-saml",
        tenant_id="acme",
        display_name="Acme SAML",
        settings=saml_settings,
        mapping=saml_mapping,
    )
    hub = Authub(
        identity_providers=InMemoryIdentityProviderStore([connection]),
        tokens=JwtTokenService.hs256("s" * 32),
        state_secret="x" * 32,
    )
    app = FastAPI()
    hub.attach(app)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        login = await client.get("/auth/acme-saml/login", follow_redirects=False)
        assert login.status_code == 302
        redirect_url = login.headers["location"]
        assert "SAMLRequest=" in redirect_url

        state_cookie = client.cookies.get(STATE_COOKIE)
        assert state_cookie, "state cookie must be present after login"

        request_id = extract_request_id(redirect_url)
        saml_response_b64 = build_saml_response(
            request_id=request_id, key_pem=key_pem, cert_pem=cert_pem
        )

        callback = await client.post(
            "/auth/acme-saml/callback",
            data={"SAMLResponse": saml_response_b64, "RelayState": "/"},
        )
        assert callback.status_code == 200, callback.text
        body = callback.json()
        assert "access_token" in body

        claims = await hub.verify_token(body["access_token"])
        assert claims.tenant_id == "acme"
        assert claims.email is not None


async def test_replay_without_in_response_to_rejected(
    idp_keys: tuple[bytes, bytes], saml_settings: SamlSettings
) -> None:
    key_pem, cert_pem = idp_keys
    protocol = SamlProtocol()
    conn = make_conn(saml_settings)
    begin = await protocol.begin(idp=conn, callback_url=ACS_URL, return_to="/")
    request_id = extract_request_id(begin.redirect_url)

    saml_response = build_saml_response(
        request_id=request_id,
        key_pem=key_pem,
        cert_pem=cert_pem,
        sc_in_response_to="",
    )
    with pytest.raises(ProtocolError):
        await protocol.complete(
            request=post_request("/cb", {"SAMLResponse": saml_response}),
            idp=conn,
            callback_url=ACS_URL,
            flow_state=begin.flow_state,
        )


async def test_missing_audience_rejected(
    idp_keys: tuple[bytes, bytes], saml_settings: SamlSettings
) -> None:
    key_pem, cert_pem = idp_keys
    protocol = SamlProtocol()
    conn = make_conn(saml_settings)
    begin = await protocol.begin(idp=conn, callback_url=ACS_URL, return_to="/")
    request_id = extract_request_id(begin.redirect_url)

    saml_response = build_saml_response(
        request_id=request_id,
        key_pem=key_pem,
        cert_pem=cert_pem,
        include_audience=False,
    )
    with pytest.raises(ProtocolError):
        await protocol.complete(
            request=post_request("/cb", {"SAMLResponse": saml_response}),
            idp=conn,
            callback_url=ACS_URL,
            flow_state=begin.flow_state,
        )


async def test_sha1_signature_rejected(
    idp_keys: tuple[bytes, bytes], saml_settings: SamlSettings
) -> None:
    key_pem, cert_pem = idp_keys
    protocol = SamlProtocol()
    conn = make_conn(saml_settings)
    begin = await protocol.begin(idp=conn, callback_url=ACS_URL, return_to="/")
    request_id = extract_request_id(begin.redirect_url)

    saml_response = build_saml_response(
        request_id=request_id,
        key_pem=key_pem,
        cert_pem=cert_pem,
        sign_algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        digest_algorithm="http://www.w3.org/2000/09/xmldsig#sha1",
    )
    with pytest.raises(ProtocolError):
        await protocol.complete(
            request=post_request("/cb", {"SAMLResponse": saml_response}),
            idp=conn,
            callback_url=ACS_URL,
            flow_state=begin.flow_state,
        )
