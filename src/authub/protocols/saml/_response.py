from __future__ import annotations

import base64
import calendar
import re as _re
from datetime import UTC, datetime
from typing import Any

from lxml import etree

from authub.protocols.saml._constants import (
    ALLOWED_CLOCK_DRIFT,
    ASSERTION_SIGNATURE_XPATH,
    CM_BEARER,
    NS_SAML,
    NS_SAMLP,
    NSMAP,
    RESPONSE_SIGNATURE_XPATH,
    STATUS_SUCCESS,
)
from authub.protocols.saml._xml import (
    element_text,
    query,
    to_etree,
    validate_xml,
)
from authub.protocols.saml._xmlsec import validate_node_sign, validate_sign

_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_TIME_FORMAT_MS = "%Y-%m-%dT%H:%M:%S.%fZ"
_TIME_RE = _re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d*)?Z?$")


def _parse_time(timestr: str) -> int:
    try:
        dt = datetime.strptime(timestr, _TIME_FORMAT)
    except ValueError:
        try:
            dt = datetime.strptime(timestr, _TIME_FORMAT_MS)
        except ValueError:
            m = _TIME_RE.match(timestr)
            if not m:
                raise ValueError(f"Cannot parse SAML timestamp: {timestr!r}") from None
            dt = datetime.strptime(m.group(1) + "Z", _TIME_FORMAT)
    return calendar.timegm(dt.utctimetuple())


def _now() -> int:
    return calendar.timegm(datetime.now(UTC).utctimetuple())


class SamlResponseValidator:
    def __init__(
        self,
        *,
        sp_entity_id: str,
        idp_entity_id: str,
        acs_url: str,
        cert_pem: bytes,
        want_assertions_signed: bool,
        want_response_signed: bool,
    ) -> None:
        self._sp_entity_id = sp_entity_id
        self._idp_entity_id = idp_entity_id
        self._acs_url = acs_url
        self._cert_pem = cert_pem
        self._want_assertions_signed = want_assertions_signed
        self._want_response_signed = want_response_signed

    def parse_and_validate(
        self,
        saml_response_b64: str,
        request_id: str,
    ) -> dict[str, Any]:
        raw = base64.b64decode(saml_response_b64)
        document = to_etree(raw)

        self._check_version(document)
        self._check_id_present(document)
        self._check_status(document)
        self._check_num_assertions(document)

        res = validate_xml(document, "saml-schema-protocol-2.0.xsd")
        if isinstance(res, str):
            raise ValueError("SAML Response does not match saml-schema-protocol-2.0.xsd")

        self._check_in_response_to(document, request_id)
        self._check_conditions(document)
        self._validate_timestamps(document)
        self._check_authn_statement(document)
        self._check_destination(document)
        self._check_audience(document)
        self._check_issuers(document)
        self._check_subject_confirmation(document, request_id)
        self._verify_signatures(document)

        return self._extract_claims(document)

    def _check_version(self, doc: etree._Element) -> None:
        if doc.get("Version") != "2.0":
            raise ValueError(f"Unsupported SAML version: {doc.get('Version')!r}")

    def _check_id_present(self, doc: etree._Element) -> None:
        if doc.get("ID") is None:
            raise ValueError("Missing ID attribute on SAML Response")

    def _check_status(self, doc: etree._Element) -> None:
        status_nodes = query(doc, "/samlp:Response/samlp:Status")
        if len(status_nodes) != 1:
            raise ValueError("Missing Status element in SAML Response")
        code_nodes = query(doc, "/samlp:Response/samlp:Status/samlp:StatusCode", status_nodes[0])
        if len(code_nodes) != 1:
            raise ValueError("Missing StatusCode in SAML Response")
        code: str = code_nodes[0].values()[0]
        if code != STATUS_SUCCESS:
            short = code.split(":")[-1]
            raise ValueError(f"SAML Status was not Success: {short}")

    def _check_num_assertions(self, doc: etree._Element) -> None:
        enc = query(doc, "//saml:EncryptedAssertion")
        plain = query(doc, "//saml:Assertion")
        total = len(enc) + len(plain)
        if total != 1:
            raise ValueError(f"SAML Response must contain exactly 1 assertion, found {total}")
        if enc:
            raise ValueError("Encrypted SAML assertions are not yet supported")

    def _check_in_response_to(self, doc: etree._Element, request_id: str) -> None:
        irt = doc.get("InResponseTo")
        if irt is not None and irt != request_id:
            raise ValueError(f"InResponseTo mismatch: expected {request_id!r}, got {irt!r}")

    def _query_assertion(self, doc: etree._Element, xpath_suffix: str) -> list[Any]:
        assertion_expr = "/saml:Assertion"
        sig_expr = "/ds:Signature/ds:SignedInfo/ds:Reference"
        assertion_ref_nodes = query(doc, "/samlp:Response" + assertion_expr + sig_expr)

        if not assertion_ref_nodes:
            msg_ref_nodes = query(doc, "/samlp:Response" + sig_expr)
            if msg_ref_nodes:
                msg_id = msg_ref_nodes[0].get("URI", "")[1:]
                base = "/samlp:Response[@ID=$tagid]" + assertion_expr
                return query(doc, base + xpath_suffix, tagid=msg_id)
            return query(doc, "/samlp:Response" + assertion_expr + xpath_suffix)
        assertion_id = assertion_ref_nodes[0].get("URI", "")[1:]
        base = "/samlp:Response" + assertion_expr + "[@ID=$tagid]"
        return query(doc, base + xpath_suffix, tagid=assertion_id)

    def _check_conditions(self, doc: etree._Element) -> None:
        cond_nodes = self._query_assertion(doc, "/saml:Conditions")
        if len(cond_nodes) != 1:
            raise ValueError("The Assertion must include exactly one Conditions element")

    def _validate_timestamps(self, doc: etree._Element) -> None:
        now = _now()
        cond_nodes = self._query_assertion(doc, "/saml:Conditions")
        for cond in cond_nodes:
            nb = cond.get("NotBefore")
            nooa = cond.get("NotOnOrAfter")
            if nb and _parse_time(nb) > now + ALLOWED_CLOCK_DRIFT:
                raise ValueError("SAML Conditions: assertion not yet valid (NotBefore)")
            if nooa and _parse_time(nooa) + ALLOWED_CLOCK_DRIFT <= now:
                raise ValueError("SAML Conditions: assertion has expired (NotOnOrAfter)")

    def _check_authn_statement(self, doc: etree._Element) -> None:
        nodes = self._query_assertion(doc, "/saml:AuthnStatement")
        if len(nodes) != 1:
            raise ValueError("The Assertion must include exactly one AuthnStatement element")

    def _check_destination(self, doc: etree._Element) -> None:
        destination = doc.get("Destination")
        if destination is None:
            return
        if not destination:
            raise ValueError("SAML Response has an empty Destination attribute")
        acs = self._acs_url.rstrip("/")
        dest = destination.rstrip("/")
        if acs.lower() != dest.lower():
            raise ValueError(
                f"SAML Response Destination {destination!r} "
                f"does not match ACS URL {self._acs_url!r}"
            )

    def _check_audience(self, doc: etree._Element) -> None:
        audience_nodes = self._query_assertion(
            doc, "/saml:Conditions/saml:AudienceRestriction/saml:Audience"
        )
        audiences = [element_text(n) for n in audience_nodes if element_text(n)]
        if not audiences:
            raise ValueError("SAML assertion is missing AudienceRestriction")
        if self._sp_entity_id not in audiences:
            raise ValueError(
                f"SP entity ID {self._sp_entity_id!r} not in SAML audiences: {audiences}"
            )

    def _check_issuers(self, doc: etree._Element) -> None:
        issuers: set[str] = set()
        response_issuer_nodes = query(doc, "/samlp:Response/saml:Issuer")
        if len(response_issuer_nodes) > 1:
            raise ValueError("Multiple Issuer elements in SAML Response")
        if response_issuer_nodes:
            v = element_text(response_issuer_nodes[0])
            if v:
                issuers.add(v)

        assertion_issuer_nodes = self._query_assertion(doc, "/saml:Issuer")
        if len(assertion_issuer_nodes) != 1:
            raise ValueError("Assertion Issuer not found or multiple in SAML Response")
        v2 = element_text(assertion_issuer_nodes[0])
        if v2:
            issuers.add(v2)

        for issuer in issuers:
            if issuer != self._idp_entity_id:
                raise ValueError(f"Invalid issuer {issuer!r} (expected {self._idp_entity_id!r})")

    def _check_subject_confirmation(self, doc: etree._Element, request_id: str) -> None:
        now = _now()
        sc_nodes = self._query_assertion(doc, "/saml:Subject/saml:SubjectConfirmation")
        any_valid = False

        for sc in sc_nodes:
            method = sc.get("Method")
            if method and method != CM_BEARER:
                continue
            sc_data = sc.find("saml:SubjectConfirmationData", namespaces=NSMAP)
            if sc_data is None:
                continue
            sc_irt = sc_data.get("InResponseTo")
            if sc_irt != request_id:
                continue
            recipient = sc_data.get("Recipient")
            if recipient and recipient.rstrip("/").lower() != self._acs_url.rstrip("/").lower():
                continue
            nooa = sc_data.get("NotOnOrAfter")
            if nooa and _parse_time(nooa) <= now:
                continue
            nb = sc_data.get("NotBefore")
            if nb and _parse_time(nb) > now:
                continue
            any_valid = True
            break

        if not any_valid:
            raise ValueError("No valid SubjectConfirmation found in SAML Response")

    def _process_signed_elements(self, doc: etree._Element) -> tuple[bool, bool]:
        sign_nodes = query(doc, "//ds:Signature")
        response_tag = f"{{{NS_SAMLP}}}Response"
        assertion_tag = f"{{{NS_SAML}}}Assertion"

        has_signed_response = False
        has_signed_assertion = False
        verified_ids: list[str] = []
        verified_seis: list[str] = []

        for sign_node in sign_nodes:
            parent = sign_node.getparent()
            if parent is None:
                raise ValueError("Signature node has no parent")
            signed_element = parent.tag
            if signed_element not in (response_tag, assertion_tag):
                raise ValueError(f"Signature found on unexpected element {signed_element!r}")
            id_val = parent.get("ID")
            if not id_val:
                raise ValueError("Signed element must have an ID attribute")
            if id_val in verified_ids:
                raise ValueError(f"Duplicate ID in signed elements: {id_val!r}")
            verified_ids.append(id_val)

            ref_nodes = query(sign_node, ".//ds:Reference")
            if ref_nodes:
                uri = ref_nodes[0].get("URI", "")
                sei = uri[1:] if uri.startswith("#") else uri
                if sei and sei != id_val:
                    raise ValueError(
                        f"Reference URI {sei!r} does not match signed element ID {id_val!r}"
                    )
                if sei in verified_seis:
                    raise ValueError(f"Duplicate Reference URI: {sei!r}")
                if sei:
                    verified_seis.append(sei)

            if signed_element == response_tag:
                has_signed_response = True
            elif signed_element == assertion_tag:
                has_signed_assertion = True

        if len(sign_nodes) > 2:
            raise ValueError("Too many Signature elements in SAML Response")

        if has_signed_response:
            expected = query(doc, RESPONSE_SIGNATURE_XPATH)
            if len(expected) != 1:
                raise ValueError(f"Expected exactly 1 Response signature, found {len(expected)}")
        if has_signed_assertion:
            expected2 = query(doc, ASSERTION_SIGNATURE_XPATH)
            if len(expected2) != 1:
                raise ValueError(f"Expected exactly 1 Assertion signature, found {len(expected2)}")

        return has_signed_response, has_signed_assertion

    def _verify_signatures(self, doc: etree._Element) -> None:
        has_response_sig, has_assertion_sig = self._process_signed_elements(doc)

        if not has_response_sig and not has_assertion_sig:
            raise ValueError("No Signature found in SAML Response — rejected")

        if self._want_response_signed and not has_response_sig:
            raise ValueError("SAML Response is not signed but want_response_signed=True")
        if self._want_assertions_signed and not has_assertion_sig:
            raise ValueError("SAML Assertion is not signed but want_assertions_signed=True")

        if has_response_sig and not validate_sign(
            doc, self._cert_pem, xpath=RESPONSE_SIGNATURE_XPATH
        ):
            raise ValueError("SAML Response signature validation failed")
        if has_assertion_sig:
            sig_nodes = query(doc, ASSERTION_SIGNATURE_XPATH)
            if sig_nodes and not validate_node_sign(sig_nodes[0], doc, self._cert_pem):
                raise ValueError("SAML Assertion signature validation failed")

    def _extract_claims(self, doc: etree._Element) -> dict[str, Any]:
        attributes: dict[str, list[str]] = {}
        attr_nodes = self._query_assertion(doc, "/saml:AttributeStatement/saml:Attribute")
        for attr_node in attr_nodes:
            key = attr_node.get("Name")
            if not key:
                continue
            values: list[str] = []
            for av in attr_node.iterchildren(f"{{{NS_SAML}}}AttributeValue"):
                etree.strip_tags(av, etree.Comment)
                text = av.text
                if text:
                    text = text.strip()
                    if text:
                        values.append(text)
            attributes[key] = values

        nameid_nodes = self._query_assertion(doc, "/saml:Subject/saml:NameID")
        name_id: str | None = None
        name_id_format: str | None = None
        if nameid_nodes:
            etree.strip_tags(nameid_nodes[0], etree.Comment)
            name_id = nameid_nodes[0].text
            name_id_format = nameid_nodes[0].get("Format")

        issuer_nodes = self._query_assertion(doc, "/saml:Issuer")
        issuer: str | None = element_text(issuer_nodes[0]) if issuer_nodes else None

        claims: dict[str, Any] = dict(attributes)
        claims["name_id"] = name_id
        claims["name_id_format"] = name_id_format
        claims["issuer"] = issuer
        return claims
