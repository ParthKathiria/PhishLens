"""
Orchestrates the full protocol verification pipeline.

Call order:
  1. extract_headers()         — pull relevant fields from raw Gmail headers
  2. parse_authentication_results() — fast path: parse Google's pre-computed results
  3. lookup_spf/dkim/dmarc()   — live path: fill gaps and fetch DMARC policy

Merge strategy:
  - If Authentication-Results has a result for a protocol, use it for status.
  - Always do a live DMARC lookup to get the published_policy (p=), because
    Authentication-Results doesn't always include this in a parseable form.
  - If Authentication-Results is missing entirely (forwarded mail, etc.),
    fall back fully to live checks.

Risk level logic:
  LOW    — DMARC passes with p=reject or p=quarantine; SPF and DKIM pass
  MEDIUM — DMARC passes but p=none (monitoring only), or one of SPF/DKIM fails
  HIGH   — DMARC fails or is absent; or alignment fails; or SPF hard-fails
"""

from .header_extractor import extract_headers
from .auth_results_parser import parse_authentication_results
from .spf_checker import lookup_spf
from .dkim_checker import lookup_dkim
from .dmarc_checker import lookup_dmarc
from .models import (
    AuthStatus,
    DMARCPolicy,
    ProtocolVerificationResult,
    SPFResult,
    DKIMResult,
    DMARCResult,
)


def _compute_risk_level(
    spf: SPFResult,
    dkim: DKIMResult,
    dmarc: DMARCResult,
    alignment_pass: bool,
) -> str:
    # Hard failures: DMARC absent or failed, or alignment fails
    dmarc_failed = dmarc.status in (AuthStatus.FAIL, AuthStatus.NONE, AuthStatus.UNKNOWN)
    if dmarc_failed or not alignment_pass:
        return "high"

    # Both SPF and DKIM failed
    spf_failed = spf.status in (AuthStatus.FAIL, AuthStatus.UNKNOWN)
    dkim_failed = dkim.status in (AuthStatus.FAIL, AuthStatus.UNKNOWN)
    if spf_failed and dkim_failed:
        return "high"

    # DMARC passes but policy is none (monitoring only, no enforcement)
    policy = dmarc.published_policy or dmarc.reported_policy
    if policy == DMARCPolicy.NONE:
        return "medium"

    # One of SPF/DKIM failed, but not both (DMARC can pass on one)
    if spf_failed or dkim_failed:
        return "medium"

    # All checks pass with an enforcing policy
    return "low"


def _determine_alignment(dkim: DKIMResult, spf: SPFResult, from_domain: str | None) -> bool:
    """
    DMARC alignment passes if either DKIM or SPF authenticates the From: domain.

    DKIM alignment: dkim.aligns_with_from (computed in dkim_checker)
    SPF alignment:  spf.domain matches from_domain (relaxed: org domain match)
    """
    if dkim.aligns_with_from:
        return True

    if spf.domain and from_domain:
        spf_dom = spf.domain.lower()
        from_dom = from_domain.lower()
        if spf_dom == from_dom:
            return True
        # Relaxed: from_domain is a subdomain of spf_domain
        if from_dom.endswith(f".{spf_dom}"):
            return True

    return False


async def verify_headers(raw_headers: list[dict]) -> ProtocolVerificationResult:
    """
    Full protocol verification pipeline.

    `raw_headers` is the Gmail API headers array:
      [{"name": "From", "value": "..."}, {"name": "Authentication-Results", "value": "..."}, ...]
    """
    # Step 1: extract the fields we care about
    parsed = extract_headers(raw_headers)

    # Step 2: fast path — parse pre-computed auth results
    spf, dkim, dmarc = parse_authentication_results(
        parsed.authentication_results or ""
    )

    # Step 3: live DKIM lookup — needed to populate signing_domain and aligns_with_from
    # even when Authentication-Results gave us the status, because the header
    # doesn't always include the d= and s= fields in a consistent location.
    if parsed.dkim_signature:
        live_dkim = await lookup_dkim(parsed.dkim_signature, parsed.from_domain)
        # Prefer live signing_domain/selector/alignment; keep fast-path status
        # if it was more informative (e.g. explicit pass from Google).
        if dkim.status == AuthStatus.UNKNOWN:
            dkim = live_dkim
        else:
            dkim = DKIMResult(
                status=dkim.status,
                signing_domain=live_dkim.signing_domain or dkim.signing_domain,
                selector=live_dkim.selector or dkim.selector,
                aligns_with_from=live_dkim.aligns_with_from,
                detail=dkim.detail,
            )

    # Step 4: live SPF lookup — fallback if Authentication-Results absent
    if spf.status == AuthStatus.UNKNOWN and parsed.from_domain:
        spf = await lookup_spf(parsed.from_domain)

    # Step 5: live DMARC lookup — always fetch to get published_policy (p=)
    if parsed.from_domain:
        live_dmarc = await lookup_dmarc(parsed.from_domain)
        dmarc = DMARCResult(
            status=dmarc.status if dmarc.status != AuthStatus.UNKNOWN else live_dmarc.status,
            reported_policy=dmarc.reported_policy,
            published_policy=live_dmarc.published_policy,
            detail=dmarc.detail or live_dmarc.detail,
        )

    # Step 6: compute alignment and risk
    alignment_pass = _determine_alignment(dkim, spf, parsed.from_domain)
    risk_level = _compute_risk_level(spf, dkim, dmarc, alignment_pass)

    return ProtocolVerificationResult(
        from_domain=parsed.from_domain,
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        alignment_pass=alignment_pass,
        risk_level=risk_level,
    )
