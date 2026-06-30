"""
Tests for header_extractor.py.

These are pure unit tests — no network calls, no async, no mocking.
The extractor is deterministic string parsing so tests are simple and fast.
"""

import pytest
from email_parser.header_extractor import extract_headers, _parse_from_address


# ---------------------------------------------------------------------------
# _parse_from_address
# ---------------------------------------------------------------------------

class TestParseFromAddress:

    def test_angle_bracket_format(self):
        email, domain = _parse_from_address("PayPal <noreply@paypal.com>")
        assert email == "noreply@paypal.com"
        assert domain == "paypal.com"

    def test_bare_address(self):
        email, domain = _parse_from_address("noreply@paypal.com")
        assert email == "noreply@paypal.com"
        assert domain == "paypal.com"

    def test_subdomain(self):
        _, domain = _parse_from_address("sender@mail.paypal.com")
        assert domain == "mail.paypal.com"

    def test_case_normalised_to_lowercase(self):
        email, domain = _parse_from_address("Name <SENDER@PAYPAL.COM>")
        assert email == "sender@paypal.com"
        assert domain == "paypal.com"

    def test_returns_none_for_garbage(self):
        email, domain = _parse_from_address("not an email at all")
        assert email is None
        assert domain is None

    def test_empty_string(self):
        email, domain = _parse_from_address("")
        assert email is None
        assert domain is None


# ---------------------------------------------------------------------------
# extract_headers
# ---------------------------------------------------------------------------

class TestExtractHeaders:

    def test_extracts_standard_headers(self, headers_all_pass):
        result = extract_headers(headers_all_pass)
        assert result.from_domain == "paypal.com"
        assert result.from_email == "noreply@paypal.com"
        assert result.authentication_results is not None
        assert "dkim=pass" in result.authentication_results
        assert result.dkim_signature is not None
        assert result.message_id == "<abc123@smtp.paypal.com>"

    def test_missing_from_header(self, headers_missing_from):
        result = extract_headers(headers_missing_from)
        assert result.from_raw is None
        assert result.from_email is None
        assert result.from_domain is None
        # Other headers still extracted
        assert result.authentication_results is not None

    def test_no_auth_results(self, headers_no_auth_results):
        result = extract_headers(headers_no_auth_results)
        assert result.authentication_results is None
        assert result.from_domain == "example.org"

    def test_case_insensitive_header_lookup(self):
        """Gmail API returns header names in their original casing — we must
        handle both 'Authentication-Results' and 'authentication-results'."""
        headers = [
            {"name": "from", "value": "test@example.com"},
            {"name": "AUTHENTICATION-RESULTS", "value": "mx.google.com; spf=pass"},
        ]
        result = extract_headers(headers)
        assert result.from_domain == "example.com"
        assert result.authentication_results == "mx.google.com; spf=pass"

    def test_empty_headers_list(self):
        result = extract_headers([])
        assert result.from_raw is None
        assert result.authentication_results is None
        assert result.dkim_signature is None

    def test_display_name_spoof_extracts_actual_domain(self, headers_display_name_spoof):
        """The From: domain should be the actual sending domain (gmail.com),
        not the display name ('PayPal Security')."""
        result = extract_headers(headers_display_name_spoof)
        assert result.from_domain == "gmail.com"
        assert result.from_email == "attacker@gmail.com"
