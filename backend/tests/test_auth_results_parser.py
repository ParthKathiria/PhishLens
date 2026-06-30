"""
Tests for auth_results_parser.py.

Also pure unit tests — the parser takes a string and returns typed models.
Tests cover the realistic header formats that Gmail actually produces.
"""

import pytest
from email_parser.auth_results_parser import parse_authentication_results
from email_parser.models import AuthStatus, DMARCPolicy


class TestParseAuthenticationResults:

    def test_all_pass_extracts_correctly(self, headers_all_pass):
        auth_results_value = next(
            h["value"] for h in headers_all_pass if h["name"] == "Authentication-Results"
        )
        spf, dkim, dmarc = parse_authentication_results(auth_results_value)

        assert spf.status == AuthStatus.PASS
        assert spf.domain == "paypal.com"

        assert dkim.status == AuthStatus.PASS
        assert dkim.signing_domain == "paypal.com"
        assert dkim.selector == "pp-dkim1"

        assert dmarc.status == AuthStatus.PASS
        assert dmarc.reported_policy == DMARCPolicy.REJECT

    def test_dmarc_none_policy_parsed(self, headers_dmarc_none_policy):
        auth_value = next(
            h["value"] for h in headers_dmarc_none_policy if h["name"] == "Authentication-Results"
        )
        _, _, dmarc = parse_authentication_results(auth_value)

        assert dmarc.status == AuthStatus.PASS
        assert dmarc.reported_policy == DMARCPolicy.NONE

    def test_dkim_fail_status(self, headers_dkim_fail):
        auth_value = next(
            h["value"] for h in headers_dkim_fail if h["name"] == "Authentication-Results"
        )
        spf, dkim, dmarc = parse_authentication_results(auth_value)

        assert dkim.status == AuthStatus.FAIL
        assert spf.status == AuthStatus.PASS
        assert dmarc.status == AuthStatus.FAIL

    def test_empty_string_returns_unknowns(self):
        spf, dkim, dmarc = parse_authentication_results("")
        assert spf.status == AuthStatus.UNKNOWN
        assert dkim.status == AuthStatus.UNKNOWN
        assert dmarc.status == AuthStatus.UNKNOWN

    def test_header_with_no_semicolon(self):
        """Malformed header — just the authserv-id, nothing else."""
        spf, dkim, dmarc = parse_authentication_results("mx.google.com")
        assert spf.status == AuthStatus.UNKNOWN

    def test_semicolons_inside_spf_comment_do_not_break_parsing(self):
        """
        The SPF comment sometimes contains semicolons in edge cases.
        This test verifies that _split_outside_parens handles them correctly.
        """
        header = (
            "mx.google.com;"
            " spf=pass (google.com: permitted; see rfc)  smtp.mailfrom=test.com;"
            " dmarc=pass (p=REJECT) header.from=test.com"
        )
        spf, _, dmarc = parse_authentication_results(header)
        assert spf.status == AuthStatus.PASS
        assert dmarc.status == AuthStatus.PASS

    def test_spf_domain_extracted(self):
        header = (
            "mx.google.com;"
            " spf=pass smtp.mailfrom=example.com"
        )
        spf, _, _ = parse_authentication_results(header)
        assert spf.domain == "example.com"

    def test_dkim_signing_domain_from_header_i(self):
        """header.i=@domain.com — the @ prefix must be stripped."""
        header = (
            "mx.google.com;"
            " dkim=pass header.i=@signing.com header.s=sel1"
        )
        _, dkim, _ = parse_authentication_results(header)
        assert dkim.signing_domain == "signing.com"
        assert dkim.selector == "sel1"
