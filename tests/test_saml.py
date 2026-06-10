from __future__ import annotations

import datetime
import shutil
from pathlib import Path
from typing import cast
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import pytest
from fastapi import FastAPI
from starlette.requests import Request

pytest.importorskip("saml2")

_XMLSEC = shutil.which("xmlsec1")
pytestmark = pytest.mark.skipif(_XMLSEC is None, reason="xmlsec1 binary not installed")

if _XMLSEC is not None:
    from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
    from saml2.config import IdPConfig, SPConfig
    from saml2.metadata import create_metadata_string
    from saml2.saml import NAMEID_FORMAT_PERSISTENT, NameID
    from saml2.server import Server

    from authub import Authub, Connection, Mapping
    from authub.errors import ProtocolError
    from authub.models import SamlSettings
    from authub.protocols.saml import SamlProtocol
    from authub.state import STATE_COOKIE
    from authub.stores.memory import InMemoryConnectionStore
    from authub.tokens.jwt import JwtTokenService

SP_ENTITY = "https://app.test/saml/metadata"
IDP_ENTITY = "https://idp.test/metadata"
ACS_URL = "http://testserver/auth/acme-saml/callback"
AUTHN = {
    "class_ref": "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
    "authn_auth": "https://idp.test/login",
}


def make_self_signed_cert(tmp_path: Path) -> tuple[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

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
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_path, cert_path = tmp_path / "idp.key", tmp_path / "idp.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(key_path), str(cert_path)


def make_sp_metadata() -> str:
    sp_config = SPConfig()
    sp_config.load(
        {
            "entityid": SP_ENTITY,
            "service": {
                "sp": {"endpoints": {"assertion_consumer_service": [(ACS_URL, BINDING_HTTP_POST)]}}
            },
            "xmlsec_binary": _XMLSEC,
        }
    )
    return cast(str, create_metadata_string(None, config=sp_config).decode())


@pytest.fixture
def idp(tmp_path: Path) -> Server:
    key_file, cert_file = make_self_signed_cert(tmp_path)
    config = IdPConfig()
    config.load(
        {
            "entityid": IDP_ENTITY,
            "service": {
                "idp": {
                    "endpoints": {
                        "single_sign_on_service": [("https://idp.test/sso", BINDING_HTTP_REDIRECT)]
                    },
                    "policy": {
                        "default": {
                            "lifetime": {"minutes": 15},
                            "attribute_restrictions": None,
                        }
                    },
                }
            },
            "key_file": key_file,
            "cert_file": cert_file,
            "xmlsec_binary": _XMLSEC,
            "metadata": {"inline": [make_sp_metadata()]},
        }
    )
    return Server(config=config)


@pytest.fixture
def settings(idp: Server) -> SamlSettings:
    idp_metadata = create_metadata_string(None, config=idp.config).decode()
    return SamlSettings(
        sp_entity_id=SP_ENTITY,
        idp_metadata_xml=idp_metadata,
        idp_entity_id=IDP_ENTITY,
    )


def make_conn(settings: SamlSettings) -> Connection:
    return Connection(id="acme-saml", tenant_id="acme", display_name="Acme SAML", settings=settings)


def post_request(path: str, data: dict[str, str]) -> Request:
    body = urlencode(data).encode()

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "http",
            "server": ("t", 80),
            "path": path,
            "query_string": b"",
            "headers": [
                (b"content-type", b"application/x-www-form-urlencoded"),
                (b"content-length", str(len(body)).encode()),
            ],
        },
        receive,
    )


def idp_handle_request(idp: Server, redirect_url: str, *, sign: bool = True) -> str:
    query = parse_qs(urlsplit(redirect_url).query)
    parsed = idp.parse_authn_request(query["SAMLRequest"][0], BINDING_HTTP_REDIRECT)
    resp_args = idp.response_args(parsed.message)
    resp_args.pop("binding", None)
    response_xml = idp.create_authn_response(
        identity={"mail": ["ada@acme.test"], "cn": ["Ada"]},
        userid="ada",
        name_id=NameID(format=NAMEID_FORMAT_PERSISTENT, text="ada-persistent-id"),
        authn=AUTHN,
        sign_response=sign,
        sign_assertion=sign,
        **resp_args,
    )
    http_args = idp.apply_binding(
        BINDING_HTTP_POST,
        str(response_xml),
        destination=ACS_URL,
        relay_state="/",
        response=True,
    )
    return cast(str, http_args["data"]["SAMLResponse"])


async def test_full_saml_round_trip(idp: Server, settings: SamlSettings) -> None:
    protocol = SamlProtocol()
    conn = make_conn(settings)
    begin = await protocol.begin(conn=conn, callback_url=ACS_URL, return_to="/")
    assert "SAMLRequest=" in begin.redirect_url
    assert begin.flow_state.request_id

    saml_response = idp_handle_request(idp, begin.redirect_url)
    raw = await protocol.complete(
        request=post_request("/cb", {"SAMLResponse": saml_response, "RelayState": "/"}),
        conn=conn,
        callback_url=ACS_URL,
        flow_state=begin.flow_state,
    )
    assert raw.claims["mail"] == ["ada@acme.test"]
    assert raw.claims["name_id"] == "ada-persistent-id"
    assert raw.claims["issuer"] == IDP_ENTITY


async def test_unsigned_response_rejected(idp: Server, settings: SamlSettings) -> None:
    protocol = SamlProtocol()
    conn = make_conn(settings)
    begin = await protocol.begin(conn=conn, callback_url=ACS_URL, return_to="/")
    saml_response = idp_handle_request(idp, begin.redirect_url, sign=False)
    with pytest.raises(ProtocolError):
        await protocol.complete(
            request=post_request("/cb", {"SAMLResponse": saml_response}),
            conn=conn,
            callback_url=ACS_URL,
            flow_state=begin.flow_state,
        )


async def test_unknown_in_response_to_rejected(idp: Server, settings: SamlSettings) -> None:
    protocol = SamlProtocol()
    conn = make_conn(settings)
    begin = await protocol.begin(conn=conn, callback_url=ACS_URL, return_to="/")
    saml_response = idp_handle_request(idp, begin.redirect_url)
    forged_state = begin.flow_state.model_copy(update={"request_id": "id-forged"})
    with pytest.raises(ProtocolError):
        await protocol.complete(
            request=post_request("/cb", {"SAMLResponse": saml_response}),
            conn=conn,
            callback_url=ACS_URL,
            flow_state=forged_state,
        )


async def test_saml_login_through_http_router(idp: Server, settings: SamlSettings) -> None:
    """Full SAML SP flow through the Authub HTTP router: login → IdP → callback → token."""
    saml_mapping = Mapping(external_id="name_id", email="mail", name="cn")
    connection = Connection(
        id="acme-saml",
        tenant_id="acme",
        display_name="Acme SAML",
        settings=settings,
        mapping=saml_mapping,
    )
    hub = Authub(
        connections=InMemoryConnectionStore([connection]),
        tokens=JwtTokenService.hs256("s" * 32),
        state_secret="x" * 32,
    )
    app = FastAPI()
    hub.attach(app)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. GET /auth/acme-saml/login → redirect to IdP with SAMLRequest
        login = await client.get("/auth/acme-saml/login", follow_redirects=False)
        assert login.status_code == 302
        redirect_url = login.headers["location"]
        assert "SAMLRequest=" in redirect_url

        # State cookie must be set
        state_cookie = client.cookies.get(STATE_COOKIE)
        assert state_cookie, "state cookie must be present after login"

        # 2. Fabricate the signed SAMLResponse from the in-process IdP
        saml_response_b64 = idp_handle_request(idp, redirect_url)

        # 3. POST SAMLResponse to /auth/acme-saml/callback as form data
        # (state cookie is already in client.cookies)
        callback = await client.post(
            "/auth/acme-saml/callback",
            data={"SAMLResponse": saml_response_b64, "RelayState": "/"},
        )
        assert callback.status_code == 200, callback.text
        body = callback.json()
        assert "access_token" in body

        # 4. Verify the issued token carries the correct tenant
        claims = await hub.verify_token(body["access_token"])
        assert claims.tenant_id == "acme"
        assert claims.email is not None
