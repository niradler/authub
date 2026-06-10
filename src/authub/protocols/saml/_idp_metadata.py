from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from authub.protocols.saml._constants import BINDING_HTTP_REDIRECT
from authub.protocols.saml._xml import element_text, query, to_etree
from authub.protocols.saml._xmlsec import format_cert


@dataclass(frozen=True)
class IdpInfo:
    entity_id: str
    sso_url: str
    cert_pem: bytes


@lru_cache(maxsize=128)
def _parse_idp_metadata_cached(xml: str, entity_id: str | None) -> IdpInfo:
    return _parse_idp_metadata_impl(xml, entity_id)


def parse_idp_metadata(xml: str, entity_id: str | None = None) -> IdpInfo:
    return _parse_idp_metadata_cached(xml, entity_id)


def _parse_idp_metadata_impl(xml: str, entity_id: str | None = None) -> IdpInfo:
    dom = to_etree(xml.encode() if isinstance(xml, str) else xml)

    path = "//md:EntityDescriptor"
    if entity_id:
        path += f"[@entityID='{entity_id}']"
    entity_nodes = query(dom, path)
    if not entity_nodes:
        raise ValueError("No EntityDescriptor found in IdP metadata")

    entity_node = entity_nodes[0]
    idp_nodes = query(entity_node, "./md:IDPSSODescriptor")
    if not idp_nodes:
        raise ValueError("No IDPSSODescriptor found in IdP metadata")

    idp_node = idp_nodes[0]
    found_entity_id: str | None = entity_node.get("entityID")
    if not found_entity_id:
        raise ValueError("EntityDescriptor missing entityID")

    sso_nodes = query(
        idp_node,
        f"./md:SingleSignOnService[@Binding='{BINDING_HTTP_REDIRECT}']",
    )
    if not sso_nodes:
        raise ValueError(
            f"No HTTP-Redirect SSO service found in IdP metadata for {found_entity_id}"
        )
    sso_url: str | None = sso_nodes[0].get("Location")
    if not sso_url:
        raise ValueError("SingleSignOnService missing Location attribute")

    _signing_xpath = (
        "./md:KeyDescriptor[not(contains(@use, 'encryption'))]"
        "/ds:KeyInfo/ds:X509Data/ds:X509Certificate"
    )
    signing_nodes = query(idp_node, _signing_xpath)
    if not signing_nodes:
        raise ValueError(f"No signing certificate found in IdP metadata for {found_entity_id}")

    raw_cert = element_text(signing_nodes[0]) or ""
    cert_pem = format_cert(raw_cert.replace(" ", "")).encode()

    return IdpInfo(entity_id=found_entity_id, sso_url=sso_url, cert_pem=cert_pem)
