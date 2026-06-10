from __future__ import annotations

import asyncio
import time

from authub.protocols.saml._idp_metadata import _parse_idp_metadata_cached, parse_idp_metadata
from tests.conftest import (
    exchange_code_for_tokens,
    get_code_via_login,
    make_bare_client,
    make_bare_idp,
    rotate_refresh,
)

_N_SAMPLES = 20
_JWKS_BUDGET_MS = 200.0
_USERINFO_BUDGET_MS = 300.0
_TOKEN_EXCHANGE_BUDGET_MS = 800.0
_CONCURRENCY_BUDGET_S = 30.0
_CONCURRENT_LOGINS = 50


async def _median(values: list[float]) -> float:
    sorted_vals = sorted(values)
    mid = len(sorted_vals) // 2
    if len(sorted_vals) % 2 == 1:
        return sorted_vals[mid]
    return (sorted_vals[mid - 1] + sorted_vals[mid]) / 2.0


async def test_jwks_latency_budget() -> None:
    """Median /jwks latency across 20 sequential calls must be under 200 ms in-process."""
    idp, _ = make_bare_idp()
    async with make_bare_client(idp) as client:
        await client.get("/idp/jwks")

        samples: list[float] = []
        for _ in range(_N_SAMPLES):
            t0 = time.perf_counter()
            resp = await client.get("/idp/jwks")
            elapsed_ms = (time.perf_counter() - t0) * 1000
            assert resp.status_code == 200
            samples.append(elapsed_ms)

    med = await _median(samples)
    print(f"\n[perf] /jwks median={med:.1f}ms budget={_JWKS_BUDGET_MS}ms")
    assert med < _JWKS_BUDGET_MS, f"/jwks median {med:.1f}ms exceeded budget {_JWKS_BUDGET_MS}ms"


async def test_userinfo_latency_budget() -> None:
    """Median /userinfo latency (with valid token) across 20 calls must be under 300 ms."""
    idp, _ = make_bare_idp()
    async with make_bare_client(idp) as client:
        code = await get_code_via_login(client, scope="openid email")
        tokens = await exchange_code_for_tokens(client, code)
        access_token = str(tokens["access_token"])

        await client.get("/idp/userinfo", headers={"Authorization": f"Bearer {access_token}"})

        samples: list[float] = []
        for _ in range(_N_SAMPLES):
            t0 = time.perf_counter()
            resp = await client.get(
                "/idp/userinfo", headers={"Authorization": f"Bearer {access_token}"}
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000
            assert resp.status_code == 200
            samples.append(elapsed_ms)

    med = await _median(samples)
    print(f"\n[perf] /userinfo median={med:.1f}ms budget={_USERINFO_BUDGET_MS}ms")
    assert med < _USERINFO_BUDGET_MS, (
        f"/userinfo median {med:.1f}ms exceeded budget {_USERINFO_BUDGET_MS}ms"
    )


async def test_token_exchange_latency_budget() -> None:
    """Median full token exchange latency across 20 calls must be under 800 ms in-process."""
    idp, _ = make_bare_idp()
    async with make_bare_client(idp) as client:
        warm_code = await get_code_via_login(
            client, scope="openid email", state="warm0", nonce="w0"
        )
        await exchange_code_for_tokens(client, warm_code)

        samples: list[float] = []
        for i in range(_N_SAMPLES):
            code = await get_code_via_login(
                client, scope="openid email", state=f"s{i}", nonce=f"n{i}"
            )
            t0 = time.perf_counter()
            resp = await exchange_code_for_tokens(client, code)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            assert resp.get("access_token") is not None
            samples.append(elapsed_ms)

    med = await _median(samples)
    print(f"\n[perf] token exchange median={med:.1f}ms budget={_TOKEN_EXCHANGE_BUDGET_MS}ms")
    assert med < _TOKEN_EXCHANGE_BUDGET_MS, (
        f"token exchange median {med:.1f}ms exceeded budget {_TOKEN_EXCHANGE_BUDGET_MS}ms"
    )


async def test_concurrent_logins_all_succeed_distinct_tokens() -> None:
    """50 concurrent credential logins all succeed and produce distinct codes/tokens."""
    idp, _ = make_bare_idp()
    async with make_bare_client(idp) as client:

        async def one_login(i: int) -> str:
            code = await get_code_via_login(
                client,
                scope="openid email",
                state=f"concurrent-{i}",
                nonce=f"cn{i}",
            )
            tokens = await exchange_code_for_tokens(client, code)
            return str(tokens["access_token"])

        t0 = time.perf_counter()
        access_tokens = await asyncio.gather(*[one_login(i) for i in range(_CONCURRENT_LOGINS)])
        wall_time = time.perf_counter() - t0

    print(f"\n[perf] {_CONCURRENT_LOGINS} concurrent logins wall_time={wall_time:.2f}s")
    assert len(set(access_tokens)) == _CONCURRENT_LOGINS, "tokens must be distinct"
    assert wall_time < _CONCURRENCY_BUDGET_S, (
        f"concurrent logins took {wall_time:.2f}s, budget {_CONCURRENCY_BUDGET_S}s"
    )


async def test_saml_metadata_cache_hit() -> None:
    """parse_idp_metadata called twice with same args → second call is a cache hit."""
    sample_xml = """<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://idp.example.test/metadata">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIBkTCB+wIJAJemGJsZBCFDMA0GCSqGSIb3DQEBCwUAMBExDzANBgNV
BAMTBnRlc3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNVBAMTBnRlc3Rj
YTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29Fi0C
lBQ0EHkAGiEYrDSMR2JXRs4AqS1r1GnrBkXEWxMRzHSwOXFIaS8GCVQ0nBuIoSP+/Y7gJmxLSU9nBm
CDlhzBZ5B0nGa0jqmBBMqZ5Z5Z5Z5Z5Z5Z5Z5Z5Z5Z5Z5CAwEAATANBgkqhkiG9w0BAQsFAAOBgQCk
GCR/mOmMpXUUAd+PtGkSPJZk+B4MCIfNdwM7OonLiB/JLM47OIxCJm4DtXHtpFCq</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://idp.example.test/sso" />
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""

    entity_id = "https://idp.example.test/metadata"

    _parse_idp_metadata_cached.cache_clear()

    info_before = _parse_idp_metadata_cached.cache_info()
    assert info_before.hits == 0

    parse_idp_metadata(sample_xml, entity_id)
    after_first = _parse_idp_metadata_cached.cache_info()
    assert after_first.misses >= 1

    parse_idp_metadata(sample_xml, entity_id)
    after_second = _parse_idp_metadata_cached.cache_info()
    assert after_second.hits >= after_first.hits + 1

    _parse_idp_metadata_cached.cache_clear()


async def test_refresh_rotation_latency_budget() -> None:
    """Median refresh token rotation latency across 10 calls must be under 300 ms in-process."""
    budget_ms = 300.0
    n = 10
    idp, _ = make_bare_idp()
    async with make_bare_client(idp) as client:
        code = await get_code_via_login(client, scope="openid offline_access")
        tokens = await exchange_code_for_tokens(client, code)
        current_rt = str(tokens["refresh_token"])

        warm = await rotate_refresh(client, current_rt)
        current_rt = str(warm["refresh_token"])

        samples: list[float] = []
        for _ in range(n):
            t0 = time.perf_counter()
            rotated = await rotate_refresh(client, current_rt)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            assert rotated.get("access_token") is not None, f"rotation failed: {rotated}"
            current_rt = str(rotated["refresh_token"])
            samples.append(elapsed_ms)

    med = await _median(samples)
    print(f"\n[perf] refresh rotation median={med:.1f}ms budget={budget_ms}ms")
    assert med < budget_ms, f"refresh rotation median {med:.1f}ms exceeded budget {budget_ms}ms"
