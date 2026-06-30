"""
Live SPF record lookup for a sender domain.

What we're doing here vs. what the receiving mail server does:
  A real SPF *evaluation* (RFC 7208) is complex — it follows include: chains
  recursively, checks ip4:/ip6: CIDRs against the actual sending IP, and has
  a 10-DNS-lookup limit. That evaluation is what Google's servers already did
  and stamped in Authentication-Results.

  What we do instead: fetch the raw SPF TXT record and extract signals from
  it. Specifically, we look for the "all" mechanism qualifier which tells us
  how aggressively the domain restricts senders:
    -all  hard fail    → only authorized senders; strong signal
    ~all  softfail     → unauthorized senders flagged but not rejected; common
    ?all  neutral      → domain makes no assertion
    +all  pass all     → anyone can send as this domain; very weak, suspicious

  A domain with no SPF record at all is also a signal — legitimate bulk
  senders almost always publish one.
"""

import re
from .doh_client import query_txt_records
from .models import AuthStatus, SPFResult


def _parse_all_mechanism(spf_record: str) -> AuthStatus:
    """
    Extract the catch-all qualifier from an SPF record's "all" mechanism.

    The "all" mechanism is always the last one and defines what happens to
    senders not matched by any earlier mechanism.
    """
    match = re.search(r"([+\-~?])all", spf_record, re.IGNORECASE)
    if not match:
        # "all" present but no qualifier defaults to "+" per RFC 7208 §4.6.2.
        # We treat it as pass-all, which is permissive.
        if "all" in spf_record.lower():
            return AuthStatus.PASS
        return AuthStatus.UNKNOWN

    qualifier = match.group(1)
    return {
        "+": AuthStatus.PASS,      # pass all — very permissive
        "-": AuthStatus.FAIL,      # hard fail — strict
        "~": AuthStatus.SOFTFAIL,  # soft fail — common, moderate
        "?": AuthStatus.NEUTRAL,   # neutral — no assertion
    }.get(qualifier, AuthStatus.UNKNOWN)


async def lookup_spf(domain: str) -> SPFResult:
    """
    Fetch and parse the SPF TXT record for `domain`.

    The SPF record (if it exists) is a TXT record on the domain itself,
    starting with "v=spf1". There should be at most one per domain.
    """
    try:
        records = await query_txt_records(domain)
    except Exception as exc:
        return SPFResult(
            status=AuthStatus.UNKNOWN,
            domain=domain,
            detail=f"DNS lookup failed: {exc}",
        )

    spf_record = next((r for r in records if r.lower().startswith("v=spf1")), None)

    if spf_record is None:
        return SPFResult(
            status=AuthStatus.NONE,
            domain=domain,
            detail="No SPF record found",
        )

    all_status = _parse_all_mechanism(spf_record)

    return SPFResult(
        status=all_status,
        domain=domain,
        detail=spf_record,
    )
