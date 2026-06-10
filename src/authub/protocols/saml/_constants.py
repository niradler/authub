from __future__ import annotations

ALLOWED_CLOCK_DRIFT = 300

NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
NS_XS = "http://www.w3.org/2001/XMLSchema"
NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
NS_XENC = "http://www.w3.org/2001/04/xmlenc#"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"

NSMAP: dict[str, str] = {
    "samlp": NS_SAMLP,
    "saml": NS_SAML,
    "ds": NS_DS,
    "xenc": NS_XENC,
    "md": NS_MD,
}

BINDING_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
BINDING_HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

CM_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"

NAMEID_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"

ALLOWED_SIGNATURE_ALGORITHMS: frozenset[str] = frozenset(
    {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
    }
)
ALLOWED_DIGEST_ALGORITHMS: frozenset[str] = frozenset(
    {
        "http://www.w3.org/2001/04/xmlenc#sha256",
        "http://www.w3.org/2001/04/xmldsig-more#sha384",
        "http://www.w3.org/2001/04/xmlenc#sha512",
    }
)

RESPONSE_SIGNATURE_XPATH = "/samlp:Response/ds:Signature"
ASSERTION_SIGNATURE_XPATH = "/samlp:Response/saml:Assertion/ds:Signature"
