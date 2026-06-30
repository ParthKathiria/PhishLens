"""
Shared fixtures for the email_parser test suite.

Real Authentication-Results headers taken from actual Gmail messages
(with personal details anonymised) so tests exercise realistic input.
"""

import pytest


# ---------------------------------------------------------------------------
# Raw header arrays (Gmail API format)
# ---------------------------------------------------------------------------

@pytest.fixture
def headers_all_pass():
    """A legitimate PayPal email — all three checks pass, p=REJECT."""
    return [
        {"name": "From", "value": "PayPal <noreply@paypal.com>"},
        {"name": "Message-ID", "value": "<abc123@smtp.paypal.com>"},
        {
            "name": "Authentication-Results",
            "value": (
                "mx.google.com;"
                " dkim=pass header.i=@paypal.com header.s=pp-dkim1 header.b=AbCdEfGh;"
                " spf=pass (google.com: domain of noreply@paypal.com"
                " designates 66.211.170.67 as permitted sender)"
                " smtp.mailfrom=paypal.com;"
                " dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com"
            ),
        },
        {
            "name": "DKIM-Signature",
            "value": "v=1; a=rsa-sha256; c=relaxed/relaxed; d=paypal.com; s=pp-dkim1; h=from:to:subject:date; bh=abc; b=xyz",
        },
    ]


@pytest.fixture
def headers_dmarc_none_policy():
    """DMARC passes but the published policy is p=none — monitoring only."""
    return [
        {"name": "From", "value": "newsletter@example.com"},
        {
            "name": "Authentication-Results",
            "value": (
                "mx.google.com;"
                " dkim=pass header.i=@example.com header.s=s1 header.b=XxXxXx;"
                " spf=pass smtp.mailfrom=example.com;"
                " dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=example.com"
            ),
        },
        {
            "name": "DKIM-Signature",
            "value": "v=1; a=rsa-sha256; d=example.com; s=s1; h=from:to; bh=abc; b=xyz",
        },
    ]


@pytest.fixture
def headers_dkim_fail():
    """DKIM fails — body was tampered with in transit."""
    return [
        {"name": "From", "value": "support@bank.com"},
        {
            "name": "Authentication-Results",
            "value": (
                "mx.google.com;"
                " dkim=fail (bad signature) header.i=@bank.com header.s=s2 header.b=BaD;"
                " spf=pass smtp.mailfrom=bank.com;"
                " dmarc=fail (p=QUARANTINE) header.from=bank.com"
            ),
        },
    ]


@pytest.fixture
def headers_no_auth_results():
    """Forwarded email — no Authentication-Results header at all."""
    return [
        {"name": "From", "value": "alice@example.org"},
        {"name": "Subject", "value": "FWD: Important"},
    ]


@pytest.fixture
def headers_missing_from():
    """Malformed email — no From header."""
    return [
        {
            "name": "Authentication-Results",
            "value": "mx.google.com; spf=pass smtp.mailfrom=somewhere.com",
        }
    ]


@pytest.fixture
def headers_display_name_spoof():
    """
    Display-name spoof: From header shows a trusted name but the actual
    sending address is from a different domain. SPF/DKIM pass for gmail.com
    but the displayed From: claims to be PayPal. DMARC alignment fails.
    """
    return [
        {"name": "From", "value": "PayPal Security <attacker@gmail.com>"},
        {
            "name": "Authentication-Results",
            "value": (
                "mx.google.com;"
                " dkim=pass header.i=@gmail.com header.s=20230601 header.b=LmNoPq;"
                " spf=pass smtp.mailfrom=gmail.com;"
                " dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=gmail.com"
            ),
        },
        {
            "name": "DKIM-Signature",
            "value": "v=1; a=rsa-sha256; d=gmail.com; s=20230601; h=from:to; bh=abc; b=xyz",
        },
    ]


# ---------------------------------------------------------------------------
# Raw DMARC TXT record strings
# ---------------------------------------------------------------------------

@pytest.fixture
def dmarc_record_reject():
    return "v=DMARC1; p=reject; sp=reject; adkim=r; aspf=r; pct=100; rua=mailto:dmarc@paypal.com"


@pytest.fixture
def dmarc_record_none():
    return "v=DMARC1; p=none; rua=mailto:reports@example.com"


@pytest.fixture
def dmarc_record_quarantine():
    return "v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc@example.com"
