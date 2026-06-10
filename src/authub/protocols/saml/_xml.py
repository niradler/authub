from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from lxml import etree

from authub.protocols.saml._constants import NSMAP

for prefix, url in NSMAP.items():
    etree.register_namespace(prefix, url)

_SCHEMAS_DIR = Path(__file__).parent / "schemas"


class _ParserConfig(threading.local):
    _default_parser: etree.XMLParser | None = None

    def get(self) -> etree.XMLParser:
        if self._default_parser is None:
            parser = etree.XMLParser(
                resolve_entities=False,
                remove_comments=True,
                no_network=True,
                remove_pis=True,
                huge_tree=False,
            )
            self._default_parser = parser
        return self._default_parser


_parser_tls = _ParserConfig()


def _parse(data: bytes) -> etree._Element:
    root = etree.fromstring(data, _parser_tls.get())
    tree = root.getroottree()
    docinfo = tree.docinfo
    if docinfo.doctype:
        raise ValueError(f"DTD forbidden in SAML XML: {docinfo.doctype!r}")
    for dtd in (docinfo.internalDTD, docinfo.externalDTD):
        if dtd is None:
            continue
        for entity in dtd.iterentities():
            raise ValueError(f"Entity declaration forbidden: {entity.name!r}")
    return root


def to_etree(xml: str | bytes | etree._Element) -> etree._Element:
    if isinstance(xml, etree._Element):
        return xml
    raw = xml.encode() if isinstance(xml, str) else xml
    return _parse(raw)


def to_string(xml: str | bytes | etree._Element) -> bytes:
    if isinstance(xml, bytes):
        return xml
    if isinstance(xml, str):
        return xml.encode()
    _cleanup_namespaces(xml)
    result: bytes = etree.tostring(xml)
    return result


def _cleanup_namespaces(el: etree._Element) -> None:
    etree.cleanup_namespaces(el, keep_ns_prefixes=["xs", "xsi", "xsd"])


def query(
    dom: etree._Element,
    xpath: str,
    context: etree._Element | None = None,
    tagid: str | None = None,
) -> list[Any]:
    source = context if context is not None else dom
    if tagid is None:
        return source.xpath(xpath, namespaces=NSMAP)  # type: ignore[no-any-return]
    return source.xpath(xpath, tagid=tagid, namespaces=NSMAP)  # type: ignore[no-any-return]


def element_text(node: etree._Element) -> str | None:
    etree.strip_tags(node, etree.Comment)
    text: str | None = node.text
    return text


def validate_xml(xml: str | bytes | etree._Element, schema_filename: str) -> etree._Element | str:
    try:
        elem = to_etree(xml)
    except Exception:
        return "unloaded_xml"
    schema_path = _SCHEMAS_DIR / schema_filename
    with schema_path.open() as f:
        xmlschema = etree.XMLSchema(etree.parse(f))
    if not xmlschema.validate(elem):
        return "invalid_xml"
    return elem
