"""
Tests for the live DNS checkers (spf, dkim, dmarc) and the verifier.

These tests mock all HTTP calls with respx so no real DNS queries are made.
This is important: tests must be deterministic and not depend on external
network state. A real _dmarc.paypal.com record could change; a mock won't.

respx works by intercepting httpx calls at the transport level. Any
httpx.get() call whose URL matches a respx.mock() pattern is intercepted
and returns the configured response instead of making a real HTTP request.
"""

import json
import pytest
import pytest_asyncio
import respx
import httpx

from email_parser.spf_checker import lookup_spf, _parse_all_mechanism
from email_parser.dkim_checker import lookup_dkim, _check_alignment
from email_parser.dmarc_checker import lookup_dmarc
from email_parser.verifier import verify_headers
from email_parser.models import AuthStatus, DMARCPolicy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _doh_response(txt_records: list[str]) -> dict:
    """Build a Cloudflare DoH JSON response containing TXT records."""
    return {
        "Status": 0,
        "Answer": [
            {"type": 16, "data": f'"{record}"'}
            for record in txt_records
        ],
    }


def _doh_nxdomain() -> dict:
    """Simulate NXDOMAIN — name doesn't exist."""
    return {"Status": 3, "Answer": []}


# ---------------------------------------------------------------------------
# SPF checker
# ---------------------------------------------------------------------------

class TestParseSPFAllMechanism:
    """Pure unit tests — no network."""

    def test_softfail(self):
        assert _parse_all_mechanism("v=spf1 include:_spf.google.com ~all") == AuthStatus.SOFTFAIL

    def test_hard_fail(self):
        assert _parse_all_mechanism("v=spf1 ip4:1.2.3.4 -all") == AuthStatus.FAIL

    def test_pass_all_permissive(self):
        assert _parse_all_mechanism("v=spf1 +all") == AuthStatus.PASS

    def test_neutral(self):
        assert _parse_all_mechanism("v=spf1 ?all") == AuthStatus.NEUTRAL

    def test_no_all_mechanism(self):
        assert _parse_all_mechanism("v=spf1 include:_spf.google.com") == AuthStatus.UNKNOWN


class TestLookupSPF:

    @respx.mock
    @pytest.mark.asyncio
    async def test_softfail_record(self):
        respx.get("https://1.1.1.1/dns-query").mock(
            return_value=httpx.Response(
                200,
                json=_doh_response(["v=spf1 include:_spf.google.com ~all"]),
            )
        )
        result = await lookup_spf("example.com")
        assert result.status == AuthStatus.SOFTFAIL
        assert result.domain == "example.com"

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_spf_record(self):
        respx.get("https://1.1.1.1/dns-query").mock(
            return_value=httpx.Response(200, json=_doh_nxdomain())
        )
        result = await lookup_spf("no-spf.example.com")
        assert result.status == AuthStatus.NONE

    @respx.mock
    @pytest.mark.asyncio
    async def test_dns_failure_returns_unknown(self):
        respx.get("https://1.1.1.1/dns-query").mock(
            side_effect=httpx.ConnectError("network down")
        )
        result = await lookup_spf("example.com")
        assert result.status == AuthStatus.UNKNOWN
        assert "DNS lookup failed" in (result.detail or "")


# ---------------------------------------------------------------------------
# DKIM checker
# ---------------------------------------------------------------------------

class TestCheckAlignment:
    """Pure unit tests for DKIM alignment logic."""

    def test_exact_match(self):
        assert _check_alignment("paypal.com", "paypal.com") is True

    def test_parent_domain_matches_subdomain(self):
        assert _check_alignment("paypal.com", "mail.paypal.com") is True

    def test_different_org_domain(self):
        assert _check_alignment("gmail.com", "paypal.com") is False

    def test_lookalike_domain(self):
        assert _check_alignment("paypal.com", "paypa1.com") is False

    def test_none_from_domain(self):
        assert _check_alignment("paypal.com", None) is False


class TestLookupDKIM:

    @respx.mock
    @pytest.mark.asyncio
    async def test_valid_key_record(self):
        respx.get("https://1.1.1.1/dns-query").mock(
            return_value=httpx.Response(
                200,
                json=_doh_response(["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN"]),
            )
        )
        sig = "v=1; a=rsa-sha256; d=paypal.com; s=pp-dkim1; h=from:to; bh=abc; b=xyz"
        result = await lookup_dkim(sig, "paypal.com")
        assert result.status == AuthStatus.PASS
        assert result.signing_domain == "paypal.com"
        assert result.selector == "pp-dkim1"
        assert result.aligns_with_from is True

    @respx.mock
    @pytest.mark.asyncio
    async def test_revoked_key(self):
        """A DKIM key with an empty p= tag has been revoked."""
        respx.get("https://1.1.1.1/dns-query").mock(
            return_value=httpx.Response(
                200,
                json=_doh_response(["v=DKIM1; k=rsa; p="]),
            )
        )
        sig = "v=1; a=rsa-sha256; d=paypal.com; s=old-key; h=from; bh=a; b=b"
        result = await lookup_dkim(sig, "paypal.com")
        assert result.status == AuthStatus.FAIL
        assert "revoked" in (result.detail or "").lower()

    @pytest.mark.asyncio
    async def test_no_dkim_signature_header(self):
        result = await lookup_dkim(None, "paypal.com")
        assert result.status == AuthStatus.NONE

    @pytest.mark.asyncio
    async def test_missing_d_tag(self):
        sig = "v=1; a=rsa-sha256; h=from; bh=abc; b=xyz"  # no d= or s=
        result = await lookup_dkim(sig, "paypal.com")
        assert result.status == AuthStatus.UNKNOWN

    @respx.mock
    @pytest.mark.asyncio
    async def test_misaligned_signing_domain(self):
        respx.get("https://1.1.1.1/dns-query").mock(
            return_value=httpx.Response(
                200,
                json=_doh_response(["v=DKIM1; k=rsa; p=SOMEPUBLICKEY"]),
            )
        )
        # Email says it's from paypal.com but DKIM is signed by gmail.com
        sig = "v=1; a=rsa-sha256; d=gmail.com; s=20230601; h=from; bh=a; b=b"
        result = await lookup_dkim(sig, "paypal.com")
        assert result.aligns_with_from is False


# ---------------------------------------------------------------------------
# DMARC checker
# ---------------------------------------------------------------------------

class TestLookupDMARC:

    @respx.mock
    @pytest.mark.asyncio
    async def test_reject_policy(self, dmarc_record_reject):
        respx.get("https://1.1.1.1/dns-query").mock(
            return_value=httpx.Response(
                200,
                json=_doh_response([dmarc_record_reject]),
            )
        )
        result = await lookup_dmarc("paypal.com")
        assert result.status == AuthStatus.PASS
        assert result.published_policy == DMARCPolicy.REJECT

    @respx.mock
    @pytest.mark.asyncio
    async def test_none_policy(self, dmarc_record_none):
        respx.get("https://1.1.1.1/dns-query").mock(
            return_value=httpx.Response(
                200,
                json=_doh_response([dmarc_record_none]),
            )
        )
        result = await lookup_dmarc("example.com")
        assert result.published_policy == DMARCPolicy.NONE

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_dmarc_record(self):
        """NXDOMAIN for both the subdomain and org domain candidates."""
        respx.get("https://1.1.1.1/dns-query").mock(
            return_value=httpx.Response(200, json=_doh_nxdomain())
        )
        result = await lookup_dmarc("no-dmarc.example.com")
        assert result.status == AuthStatus.NONE
        assert result.published_policy == DMARCPolicy.UNKNOWN

    @respx.mock
    @pytest.mark.asyncio
    async def test_subdomain_falls_back_to_org_domain(self, dmarc_record_quarantine):
        """
        _dmarc.mail.paypal.com returns NXDOMAIN, but _dmarc.paypal.com has
        a record. The checker should find it on the second attempt.
        """
        call_count = 0

        def side_effect(request, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First lookup (_dmarc.mail.paypal.com) — NXDOMAIN
                return httpx.Response(200, json=_doh_nxdomain())
            # Second lookup (_dmarc.paypal.com) — has record
            return httpx.Response(200, json=_doh_response([dmarc_record_quarantine]))

        respx.get("https://1.1.1.1/dns-query").mock(side_effect=side_effect)

        result = await lookup_dmarc("mail.paypal.com")
        assert result.status == AuthStatus.PASS
        assert result.published_policy == DMARCPolicy.QUARANTINE


# ---------------------------------------------------------------------------
# Verifier (integration test with mocked DNS)
# ---------------------------------------------------------------------------

class TestVerifyHeaders:

    @respx.mock
    @pytest.mark.asyncio
    async def test_all_pass_low_risk(self, headers_all_pass, dmarc_record_reject):
        """Full pipeline: Authentication-Results parsed + live DMARC lookup."""
        # DKIM key lookup
        respx.get("https://1.1.1.1/dns-query", params__contains={"name": "pp-dkim1._domainkey.paypal.com"}).mock(
            return_value=httpx.Response(
                200, json=_doh_response(["v=DKIM1; k=rsa; p=SOMEPUBLICKEY"])
            )
        )
        # DMARC lookup
        respx.get("https://1.1.1.1/dns-query", params__contains={"name": "_dmarc.paypal.com"}).mock(
            return_value=httpx.Response(200, json=_doh_response([dmarc_record_reject]))
        )

        result = await verify_headers(headers_all_pass)
        assert result.risk_level == "low"
        assert result.from_domain == "paypal.com"
        assert result.alignment_pass is True
        assert result.dmarc.published_policy == DMARCPolicy.REJECT

    @respx.mock
    @pytest.mark.asyncio
    async def test_dmarc_none_policy_is_medium_risk(self, headers_dmarc_none_policy, dmarc_record_none):
        respx.get("https://1.1.1.1/dns-query", params__contains={"name": "s1._domainkey.example.com"}).mock(
            return_value=httpx.Response(200, json=_doh_response(["v=DKIM1; k=rsa; p=PUBKEY"]))
        )
        respx.get("https://1.1.1.1/dns-query", params__contains={"name": "_dmarc.example.com"}).mock(
            return_value=httpx.Response(200, json=_doh_response([dmarc_record_none]))
        )

        result = await verify_headers(headers_dmarc_none_policy)
        assert result.risk_level == "medium"
        assert result.dmarc.published_policy == DMARCPolicy.NONE

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_dmarc_record_is_high_risk(self, headers_no_auth_results):
        """No Authentication-Results and no DMARC record → high risk."""
        # SPF lookup
        respx.get("https://1.1.1.1/dns-query", params__contains={"name": "example.org"}).mock(
            return_value=httpx.Response(200, json=_doh_response(["v=spf1 ~all"]))
        )
        # DMARC lookup — NXDOMAIN
        respx.get("https://1.1.1.1/dns-query", params__contains={"name": "_dmarc.example.org"}).mock(
            return_value=httpx.Response(200, json=_doh_nxdomain())
        )

        result = await verify_headers(headers_no_auth_results)
        assert result.risk_level == "high"
