from __future__ import annotations

import pytest

from authub.errors import MappingError
from authub.mapping import Mapper, extract, register_transform
from authub.models import Mapping, RawIdentity

CLAIMS = {
    "sub": "u-123",
    "email": "Ada@Example.COM",
    "name": "Ada",
    "groups": ["dev", "admin"],
    "org": {"unit": "R&D"},
}


def test_extract_dotted_path() -> None:
    assert extract(CLAIMS, "org.unit") == "R&D"
    assert extract(CLAIMS, "org.missing") is None
    assert extract(CLAIMS, "nope.deep") is None


def test_normalize_full() -> None:
    mapper = Mapper()
    identity = mapper.normalize(
        RawIdentity(claims=CLAIMS),
        Mapping(
            external_id="sub",
            email="email",
            name="name",
            roles="groups",
            extra={"unit": "org.unit"},
            transforms={"email": "lower"},
        ),
    )
    assert identity.external_id == "u-123"
    assert identity.email == "ada@example.com"
    assert identity.roles == ["dev", "admin"]
    assert identity.attributes == {"unit": "R&D"}
    assert identity.raw == CLAIMS


def test_missing_external_id_raises() -> None:
    with pytest.raises(MappingError):
        Mapper().normalize(RawIdentity(claims={"email": "a@b.co"}), Mapping(external_id="sub"))


def test_int_external_id_coerced_to_str() -> None:
    identity = Mapper().normalize(
        RawIdentity(claims={"id": 42}), Mapping(external_id="id", email=None, name=None)
    )
    assert identity.external_id == "42"


def test_list_valued_claims_take_first_scalar() -> None:
    # SAML attribute values arrive as lists
    identity = Mapper().normalize(
        RawIdentity(claims={"uid": ["u1"], "mail": ["a@b.co"]}),
        Mapping(external_id="uid", email="mail", name=None),
    )
    assert identity.external_id == "u1" and identity.email == "a@b.co"


def test_invalid_email_fails_loudly() -> None:
    with pytest.raises(MappingError):
        Mapper().normalize(RawIdentity(claims={"sub": "u1", "email": "not-an-email"}), Mapping())


def test_custom_transform() -> None:
    register_transform("first_word", lambda v: v.split()[0])
    identity = Mapper().normalize(
        RawIdentity(claims={"sub": "u1", "name": "Ada Lovelace"}),
        Mapping(email=None, transforms={"name": "first_word"}),
    )
    assert identity.name == "Ada"


def test_unknown_transform_raises() -> None:
    with pytest.raises(MappingError):
        Mapper().normalize(
            RawIdentity(claims={"sub": "u1"}),
            Mapping(email=None, name=None, transforms={"external_id": "no_such"}),
        )
