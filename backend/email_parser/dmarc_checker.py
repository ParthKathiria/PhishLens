"""
Live DMARC record lookup for a sender domain.

DMARC (RFC 7489) is a policy layer that:
  1. Requires that SPF or DKIM pass *and* that the authenticated domain
     aligns with the visible From: domain.
  2. Tells receiving servers what to do when that alignment fails:
       p=none       → do nothing (monitoring mode only)
       p=quarantine → deliver to spam
       p=reject     → block the message entirely

  The policy is published by the domain owner as a TXT record at
  _dmarc.<domain>.  We fetch it to know how seriously the domain takes
  its own protection — even if Google's authentication check passed,
  a p=none policy means failures from other receiving servers are silently
  ignored, which is relevant to our risk scoring.

DMARC TXT record example:
  v=DMARC1; p=reject; sp=reject; adkim=r; aspf=r;
  rua=mailto:dmarc-reports@paypal.com; pct=100

Key tags we parse:
  p=    policy for the domain itself
  sp=   policy for subdomains (if absent, p= applies)
  adkim alignment mode for DKIM: r=relaxed (default), s=strict
  aspf  alignment mode for SPF:  r=relaxed (default), s=strict
  pct=  percentage of mail the policy applies to (100 = all)
"""

import re
from .doh_client import query_txt_records
from .models import AuthStatus, DMARCPolicy, DMARCResult


def _parse_dmarc_tags(record: str) -> dict[str, str]:
    """Parse a DMARC TXT record into its tag=value components."""
    tags: dict[str, str] = {}
    for match in re.finditer(r"(\w+)\s*=\s*([^;]+)", record):
        tags[match.group(1).strip().lower()] = match.group(2).strip()
    return tags


def _to_policy(value: str) -> DMARCPolicy:
    try:
        return DMARCPolicy(value.lower().strip())
    except ValueError:
        return DMARCPolicy.UNKNOWN


async def lookup_dmarc(domain: str) -> DMARCResult:
    """
    Fetch and parse the DMARC TXT record for `domain`.

    The record lives at _dmarc.<domain>. If none is found, we also try
    the organizational domain one level up (e.g. mail.paypal.com → paypal.com),
    because DMARC allows inheriting the parent's policy.
    """
    candidates = [f"_dmarc.{domain}"]

    # Organizational domain fallback: if domain is a subdomain, try the parent.
    # e.g. mail.paypal.com → _dmarc.paypal.com
    parts = domain.split(".")
    if len(parts) > 2:
        org_domain = ".".join(parts[-2:])
        candidates.append(f"_dmarc.{org_domain}")

    for lookup_name in candidates:
        try:
            records = await query_txt_records(lookup_name)
        except Exception as exc:
            return DMARCResult(
                status=AuthStatus.UNKNOWN,
                detail=f"DNS lookup failed for {lookup_name}: {exc}",
            )

        dmarc_record = next(
            (r for r in records if r.lower().startswith("v=dmarc1")), None
        )

        if dmarc_record:
            tags = _parse_dmarc_tags(dmarc_record)
            policy = _to_policy(tags.get("p", ""))

            # pct= tells us what fraction of mail the policy applies to.
            # pct=100 (default) means full enforcement.
            # A low pct= is common during rollout but means partial protection.
            pct = tags.get("pct", "100")

            return DMARCResult(
                status=AuthStatus.PASS,
                published_policy=policy,
                detail=f"{dmarc_record} [from {lookup_name}, pct={pct}]",
            )

    # No DMARC record found anywhere in the domain hierarchy.
    # This is significant: without DMARC, there's no enforcement of
    # SPF/DKIM alignment, so display-name spoofing is unchecked.
    return DMARCResult(
        status=AuthStatus.NONE,
        published_policy=DMARCPolicy.UNKNOWN,
        detail=f"No DMARC record found for {domain}",
    )
