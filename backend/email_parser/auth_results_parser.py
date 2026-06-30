"""
Parses the Authentication-Results header (RFC 7601).

Google's receiving servers stamp this header on every inbound email with
the results of their own SPF, DKIM, and DMARC checks. Parsing it is our
fast path — no live DNS lookups needed.

Example header value:
    mx.google.com;
       dkim=pass header.i=@paypal.com header.s=pp-dkim1 header.b=AbCdEfGh;
       spf=pass (google.com: domain of noreply@paypal.com designates
           209.85.220.41 as permitted sender) smtp.mailfrom=paypal.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com
"""

import re
from .models import AuthStatus, DMARCPolicy, SPFResult, DKIMResult, DMARCResult


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _to_auth_status(value: str) -> AuthStatus:
    try:
        return AuthStatus(value.lower().strip())
    except ValueError:
        return AuthStatus.UNKNOWN


def _to_dmarc_policy(value: str) -> DMARCPolicy:
    try:
        return DMARCPolicy(value.lower().strip())
    except ValueError:
        return DMARCPolicy.UNKNOWN


def _split_outside_parens(text: str) -> list[str]:
    """
    Split `text` on semicolons, but ignore semicolons inside parentheses.

    Why this is necessary: the SPF segment includes a human-readable comment
    in parentheses — e.g. "(google.com: domain of ... as permitted sender)" —
    and RFC 5321 comments can technically contain semicolons. A naive
    text.split(';') would break on those.

    Example:
        'dkim=pass; spf=pass (a; b); dmarc=pass'
        → ['dkim=pass', ' spf=pass (a; b)', ' dmarc=pass']
    """
    parts: list[str] = []
    depth = 0
    buf: list[str] = []

    for ch in text:
        if ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch == ";" and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)

    if buf:
        parts.append("".join(buf))

    return parts


def _extract_kv(segment: str, after_offset: int) -> dict[str, str]:
    """
    Extract key=value pairs from the portion of a segment after the
    method=result token. Ignores anything inside parentheses.

    Keys can contain dots (e.g. smtp.mailfrom, header.i).
    Values are alphanumeric with dots, hyphens, underscores, @, /.
    """
    remainder = segment[after_offset:]
    # Strip parenthesized comments before extracting KV pairs
    remainder_no_comments = re.sub(r"\([^)]*\)", "", remainder)
    return dict(re.findall(r"([\w.]+)=([\w@._/\-]+)", remainder_no_comments))


def _extract_dkim_domain(kv: dict[str, str]) -> str | None:
    """
    The DKIM signing domain appears as header.i=@paypal.com (note the leading @)
    or sometimes header.d=paypal.com depending on the MTA version.
    """
    header_i = kv.get("header.i", "")
    if header_i.startswith("@"):
        return header_i[1:].lower()
    header_d = kv.get("header.d", "")
    if header_d:
        return header_d.lower()
    return None


def _extract_dmarc_reported_policy(segment: str) -> DMARCPolicy:
    """
    The DMARC policy the domain *publishes* is reported inside the parenthesized
    comment in the Authentication-Results segment, e.g. (p=REJECT sp=REJECT ...).
    This is distinct from whether DMARC passed or failed — even a passing DMARC
    check can have p=none, which means the domain is only monitoring, not enforcing.
    """
    comment_match = re.search(r"\(([^)]+)\)", segment)
    if not comment_match:
        return DMARCPolicy.UNKNOWN
    p_match = re.search(r"\bp=(\w+)", comment_match.group(1), re.IGNORECASE)
    if not p_match:
        return DMARCPolicy.UNKNOWN
    return _to_dmarc_policy(p_match.group(1))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class AuthResultsParseError(Exception):
    pass


def parse_authentication_results(
    header_value: str,
) -> tuple[SPFResult, DKIMResult, DMARCResult]:
    """
    Parse the Authentication-Results header into typed result objects.

    Returns a 3-tuple of (SPFResult, DKIMResult, DMARCResult).
    Any protocol not found in the header gets an UNKNOWN status — callers
    must treat UNKNOWN as a signal to fall back to live DNS lookups.
    """
    spf = SPFResult()
    dkim = DKIMResult()
    dmarc = DMARCResult()

    if not header_value or not header_value.strip():
        return spf, dkim, dmarc

    # The header starts with an authserv-id (e.g. "mx.google.com") followed
    # by a semicolon. Everything after that semicolon is the actual results.
    first_semi = header_value.find(";")
    if first_semi == -1:
        return spf, dkim, dmarc

    results_text = header_value[first_semi + 1 :]
    segments = _split_outside_parens(results_text)

    for segment in segments:
        segment = segment.strip()
        if not segment:
            continue

        # Each segment starts with "method=result"
        method_match = re.match(r"(\w+)=(\w+)", segment)
        if not method_match:
            continue

        method = method_match.group(1).lower()
        status = _to_auth_status(method_match.group(2))
        kv = _extract_kv(segment, method_match.end())

        if method == "spf":
            spf = SPFResult(
                status=status,
                domain=kv.get("smtp.mailfrom") or kv.get("smtp.helo"),
                detail=segment,
            )

        elif method == "dkim":
            spf_domain = _extract_dkim_domain(kv)
            dkim = DKIMResult(
                status=status,
                signing_domain=spf_domain,
                selector=kv.get("header.s"),
                detail=segment,
            )

        elif method == "dmarc":
            dmarc = DMARCResult(
                status=status,
                reported_policy=_extract_dmarc_reported_policy(segment),
                detail=segment,
            )

    return spf, dkim, dmarc
