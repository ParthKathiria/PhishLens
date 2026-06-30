"""
DKIM public key record lookup.

What we verify here vs. full DKIM verification:
  Full DKIM verification (RFC 6376) requires:
    1. Parse the DKIM-Signature header to get d= (domain), s= (selector),
       h= (signed headers), bh= (body hash), b= (signature).
    2. Fetch the public key at <s>._domainkey.<d> via DNS.
    3. Reconstruct the canonicalized header set and body.
    4. Verify the RSA/Ed25519 signature using the public key.

  Steps 3 and 4 require the raw email bytes (not just headers), which the
  Gmail API doesn't return in metadata format. Google's mail servers already
  did this and reported the result in Authentication-Results.

  What we do: parse d= and s= from the DKIM-Signature header, then do the
  DNS lookup to confirm the key record exists. This:
    - Gives us the authoritative signing domain for alignment checking.
    - Confirms the key hasn't been revoked (a revoked key returns p= empty).
    - Is something we can actually do with the data we have.

DKIM-Signature header format (relevant fields):
  DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
      d=paypal.com; s=pp-dkim1;
      h=from:to:subject:date;
      bh=<base64 body hash>;
      b=<base64 signature>

The DNS key record lives at:  <s>._domainkey.<d>
  e.g. pp-dkim1._domainkey.paypal.com
It contains: v=DKIM1; k=rsa; p=<base64 public key>
  An empty p= means the key has been revoked.
"""

import re
from .doh_client import query_txt_records
from .models import AuthStatus, DKIMResult


def _parse_dkim_signature(dkim_sig_header: str) -> dict[str, str]:
    """
    Parse a DKIM-Signature header into its tag=value components.

    DKIM headers are folded (line-wrapped with whitespace) so we first
    collapse whitespace, then extract all tag=value pairs.

    Tags are single-letter (v, a, c, d, s, h, bh, b, ...).
    Values end at ';' or end-of-string.
    """
    # Unfold: collapse all whitespace sequences (including newlines from folding)
    unfolded = re.sub(r"\s+", " ", dkim_sig_header)

    tags: dict[str, str] = {}
    for match in re.finditer(r"(\w+)\s*=\s*([^;]+)", unfolded):
        key = match.group(1).strip()
        value = match.group(2).strip()
        tags[key] = value

    return tags


async def lookup_dkim(dkim_signature_header: str | None, from_domain: str | None) -> DKIMResult:
    """
    Parse the DKIM-Signature header, look up the public key record in DNS,
    and determine alignment with the From: domain.
    """
    if not dkim_signature_header:
        return DKIMResult(
            status=AuthStatus.NONE,
            detail="No DKIM-Signature header present",
        )

    tags = _parse_dkim_signature(dkim_signature_header)
    signing_domain = tags.get("d", "").lower().strip()
    selector = tags.get("s", "").lower().strip()

    if not signing_domain or not selector:
        return DKIMResult(
            status=AuthStatus.UNKNOWN,
            detail="DKIM-Signature missing d= or s= tag",
        )

    # Determine alignment: does the signing domain match (or is a parent of)
    # the From: domain? We use relaxed alignment — matching the organizational
    # domain — which is what DMARC uses by default.
    aligns = _check_alignment(signing_domain, from_domain)

    # Fetch the public key record
    key_record_name = f"{selector}._domainkey.{signing_domain}"
    try:
        records = await query_txt_records(key_record_name)
    except Exception as exc:
        return DKIMResult(
            status=AuthStatus.UNKNOWN,
            signing_domain=signing_domain,
            selector=selector,
            aligns_with_from=aligns,
            detail=f"DNS lookup failed for {key_record_name}: {exc}",
        )

    key_record = next((r for r in records if "DKIM1" in r or "k=" in r or "p=" in r), None)

    if key_record is None:
        return DKIMResult(
            status=AuthStatus.FAIL,
            signing_domain=signing_domain,
            selector=selector,
            aligns_with_from=aligns,
            detail=f"No DKIM key record found at {key_record_name}",
        )

    # An empty p= tag means the key has been deliberately revoked.
    # Legitimate domains do this when rotating keys.
    p_match = re.search(r"\bp=([^;]*)", key_record)
    if p_match and not p_match.group(1).strip():
        return DKIMResult(
            status=AuthStatus.FAIL,
            signing_domain=signing_domain,
            selector=selector,
            aligns_with_from=aligns,
            detail=f"DKIM key at {key_record_name} has been revoked (p= is empty)",
        )

    return DKIMResult(
        status=AuthStatus.PASS,
        signing_domain=signing_domain,
        selector=selector,
        aligns_with_from=aligns,
        detail=key_record,
    )


def _check_alignment(signing_domain: str, from_domain: str | None) -> bool:
    """
    Relaxed DKIM alignment (DMARC default): the signing domain must be the
    same as or a parent of the From: domain.

    Examples:
      signing=paypal.com,  from=paypal.com       → True  (exact match)
      signing=paypal.com,  from=mail.paypal.com  → True  (parent domain)
      signing=paypal.com,  from=paypa1.com       → False (lookalike)
      signing=gmail.com,   from=paypal.com       → False (different org)
    """
    if not from_domain:
        return False
    if signing_domain == from_domain:
        return True
    # Parent domain check: from_domain ends with ".{signing_domain}"
    return from_domain.endswith(f".{signing_domain}")
