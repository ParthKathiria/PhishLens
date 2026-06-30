import re
from dataclasses import dataclass


@dataclass
class ParsedHeaders:
    from_raw: str | None           # raw From: header value e.g. "PayPal <noreply@paypal.com>"
    from_email: str | None         # extracted e.g. "noreply@paypal.com"
    from_domain: str | None        # extracted e.g. "paypal.com"
    authentication_results: str | None
    dkim_signature: str | None
    received_spf: str | None
    message_id: str | None


def _find_header(headers: list[dict], name: str) -> str | None:
    """Case-insensitive scan. Returns the value of the first matching header."""
    name_lower = name.lower()
    for h in headers:
        if h.get("name", "").lower() == name_lower:
            return h.get("value")
    return None


def _parse_from_address(from_value: str) -> tuple[str | None, str | None]:
    """
    Returns (email, domain) from a From: header.

    Handles two formats:
      "PayPal <noreply@paypal.com>"  — angle-bracket form (RFC 5322 display name)
      "noreply@paypal.com"           — bare address

    The angle-bracket form is what most legitimate senders use; bare addresses
    appear in automated systems. Phishing emails sometimes omit the display name
    entirely, which is itself a weak signal.
    """
    # Angle-bracket form: capture everything inside < >
    match = re.search(r"<([^>]+@([^>@]+))>", from_value)
    if match:
        email = match.group(1).strip().lower()
        domain = match.group(2).strip().lower()
        return email, domain

    # Bare email form
    match = re.search(r"([\w.+\-]+@([\w.\-]+))", from_value)
    if match:
        email = match.group(1).strip().lower()
        domain = match.group(2).strip().lower()
        return email, domain

    return None, None


def extract_headers(raw_headers: list[dict]) -> ParsedHeaders:
    """
    Takes the Gmail API headers array — [{name: str, value: str}, ...] —
    and returns only the fields the protocol verification layer needs.

    We do this in one place so every downstream module gets a clean, typed
    object instead of each re-implementing its own header lookup.
    """
    from_raw = _find_header(raw_headers, "From")
    from_email, from_domain = _parse_from_address(from_raw) if from_raw else (None, None)

    return ParsedHeaders(
        from_raw=from_raw,
        from_email=from_email,
        from_domain=from_domain,
        authentication_results=_find_header(raw_headers, "Authentication-Results"),
        dkim_signature=_find_header(raw_headers, "DKIM-Signature"),
        received_spf=_find_header(raw_headers, "Received-SPF"),
        message_id=_find_header(raw_headers, "Message-ID"),
    )
