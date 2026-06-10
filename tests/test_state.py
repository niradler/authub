from __future__ import annotations

import pytest

from authub.errors import InvalidStateError
from authub.state import BeginResult, FlowState, FlowStateCodec

SECRET = "x" * 32


def make_state() -> FlowState:
    return FlowState(
        idp_id="acme-okta",
        return_to="/app",
        state="st",
        nonce="n",
        code_verifier="v" * 43,
    )


def test_roundtrip() -> None:
    codec = FlowStateCodec(secret=SECRET)
    token = codec.encode(make_state())
    decoded = codec.decode(token)
    assert decoded == make_state()


def test_expired_rejected() -> None:
    codec = FlowStateCodec(secret=SECRET, ttl_seconds=-1)
    token = codec.encode(make_state())
    with pytest.raises(InvalidStateError):
        FlowStateCodec(secret=SECRET).decode(token)


def test_tampered_rejected() -> None:
    codec = FlowStateCodec(secret=SECRET)
    token = codec.encode(make_state())
    with pytest.raises(InvalidStateError):
        codec.decode(token[:-3] + "abc")


def test_wrong_secret_rejected() -> None:
    token = FlowStateCodec(secret=SECRET).encode(make_state())
    with pytest.raises(InvalidStateError):
        FlowStateCodec(secret="y" * 32).decode(token)


def test_authub_token_is_not_valid_state() -> None:
    codec = FlowStateCodec(secret=SECRET)
    from joserfc import jwt
    from joserfc.jwk import OctKey

    forged = jwt.encode(
        {"alg": "HS256", "typ": "JWT"},
        {"fs": make_state().model_dump(mode="json"), "exp": 9999999999},
        OctKey.import_key(SECRET),
        algorithms=["HS256"],
    )
    with pytest.raises(InvalidStateError):
        codec.decode(forged)


def test_begin_result_shape() -> None:
    result = BeginResult(redirect_url="https://idp/x", flow_state=make_state())
    assert result.redirect_url.startswith("https://")
