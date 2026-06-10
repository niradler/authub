from __future__ import annotations

import base64
import zlib
from hashlib import sha1 as _sha1
from textwrap import wrap
from typing import Any
from uuid import uuid4

import xmlsec
from lxml import etree

from authub.protocols.saml._constants import (
    ALLOWED_DIGEST_ALGORITHMS,
    ALLOWED_SIGNATURE_ALGORITHMS,
    ASSERTION_SIGNATURE_XPATH,
    RESPONSE_SIGNATURE_XPATH,
    RSA_SHA256,
    SHA256,
)
from authub.protocols.saml._xml import query, to_etree, to_string

_SIGN_ALGO_MAP: dict[str, Any] = {
    "http://www.w3.org/2000/09/xmldsig#dsa-sha1": xmlsec.Transform.DSA_SHA1,
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1": xmlsec.Transform.RSA_SHA1,
    RSA_SHA256: xmlsec.Transform.RSA_SHA256,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": xmlsec.Transform.RSA_SHA384,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": xmlsec.Transform.RSA_SHA512,
}

_DIGEST_ALGO_MAP: dict[str, Any] = {
    "http://www.w3.org/2000/09/xmldsig#sha1": xmlsec.Transform.SHA1,
    SHA256: xmlsec.Transform.SHA256,
    "http://www.w3.org/2001/04/xmldsig-more#sha384": xmlsec.Transform.SHA384,
    "http://www.w3.org/2001/04/xmlenc#sha512": xmlsec.Transform.SHA512,
}


def _algorithms_allowed(signature_node: etree._Element) -> bool:
    sig_methods = query(signature_node, ".//ds:SignedInfo/ds:SignatureMethod")
    digest_methods = query(signature_node, ".//ds:SignedInfo/ds:Reference/ds:DigestMethod")
    if not sig_methods or not digest_methods:
        return False
    for sm in sig_methods:
        if sm.get("Algorithm") not in ALLOWED_SIGNATURE_ALGORITHMS:
            return False
    return all(dm.get("Algorithm") in ALLOWED_DIGEST_ALGORITHMS for dm in digest_methods)


def format_cert(cert: str, heads: bool = True) -> str:
    x = cert.replace("\r\n", "").replace("\r", "").replace("\n", "")
    x = x.replace("-----BEGIN CERTIFICATE-----", "")
    x = x.replace("-----END CERTIFICATE-----", "")
    x = x.replace(" ", "")
    if not x:
        return ""
    if heads:
        return (
            "-----BEGIN CERTIFICATE-----\n"
            + "\n".join(wrap(x, 64))
            + "\n-----END CERTIFICATE-----\n"
        )
    return x


def b64decode(data: str | bytes) -> bytes:
    return base64.b64decode(data)


def deflate_and_b64encode(value: str | bytes) -> str:
    raw = value.encode() if isinstance(value, str) else value
    compressed = zlib.compress(raw)[2:-4]
    return base64.b64encode(compressed).decode()


def add_sign(
    xml: str | bytes | etree._Element,
    key_pem: bytes,
    cert_pem: bytes,
    sign_algorithm: str = RSA_SHA256,
    digest_algorithm: str = SHA256,
) -> bytes:
    sign_transform = _SIGN_ALGO_MAP.get(sign_algorithm, xmlsec.Transform.RSA_SHA256)
    digest_transform = _DIGEST_ALGO_MAP.get(digest_algorithm, xmlsec.Transform.SHA256)

    elem = to_etree(xml)

    signature = xmlsec.template.create(elem, xmlsec.Transform.EXCL_C14N, sign_transform, ns="ds")

    issuer_nodes = query(elem, "//saml:Issuer")
    if issuer_nodes:
        issuer_nodes[0].addnext(signature)
        elem_to_sign = issuer_nodes[0].getparent()
    else:
        elem[0].insert(0, signature)
        elem_to_sign = elem

    elem_id = elem_to_sign.get("ID")
    if elem_id is None:
        generated = "AUTHUB_" + _sha1(uuid4().bytes).hexdigest()
        elem_to_sign.attrib["ID"] = generated
        elem_id = "#" + generated
    else:
        elem_id = "#" + elem_id

    xmlsec.tree.add_ids(elem_to_sign, ["ID"])

    ref = xmlsec.template.add_reference(signature, digest_transform, uri=elem_id)
    xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)
    xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)
    key_info = xmlsec.template.ensure_key_info(signature)
    xmlsec.template.add_x509_data(key_info)

    dsig_ctx = xmlsec.SignatureContext()
    sign_key = xmlsec.Key.from_memory(key_pem, xmlsec.KeyFormat.PEM, None)
    sign_key.load_cert_from_memory(cert_pem, xmlsec.KeyFormat.PEM)
    dsig_ctx.key = sign_key
    dsig_ctx.sign(signature)

    return to_string(elem)


def validate_sign(
    xml: str | bytes | etree._Element,
    cert_pem: bytes,
    xpath: str | None = None,
) -> bool:
    elem = to_etree(xml)
    xmlsec.tree.add_ids(elem, ["ID"])

    if xpath:
        sig_nodes = query(elem, xpath)
    else:
        sig_nodes = query(elem, RESPONSE_SIGNATURE_XPATH)
        if not sig_nodes:
            sig_nodes = query(elem, ASSERTION_SIGNATURE_XPATH)

    if len(sig_nodes) != 1:
        return False

    if not _algorithms_allowed(sig_nodes[0]):
        return False

    try:
        dsig_ctx = xmlsec.SignatureContext()
        dsig_ctx.key = xmlsec.Key.from_memory(cert_pem, xmlsec.KeyFormat.CERT_PEM, None)
        dsig_ctx.set_enabled_key_data([xmlsec.KeyData.X509])
        dsig_ctx.verify(sig_nodes[0])
        return True
    except Exception:
        return False


def validate_node_sign(
    signature_node: etree._Element,
    elem: etree._Element,
    cert_pem: bytes,
) -> bool:
    xmlsec.tree.add_ids(elem, ["ID"])
    if not _algorithms_allowed(signature_node):
        return False
    try:
        dsig_ctx = xmlsec.SignatureContext()
        dsig_ctx.key = xmlsec.Key.from_memory(cert_pem, xmlsec.KeyFormat.CERT_PEM, None)
        dsig_ctx.set_enabled_key_data([xmlsec.KeyData.X509])
        dsig_ctx.verify(signature_node)
        return True
    except Exception:
        return False
