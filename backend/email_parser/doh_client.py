"""
DNS-over-HTTPS (DoH) client using Cloudflare's resolver (1.1.1.1).

Why DoH instead of standard DNS (UDP port 53)?
  The FastAPI backend runs as a normal process and could use standard DNS.
  But the Chrome extension cannot — browsers block raw UDP socket access.
  To keep the extension capable of doing its own lookups in the future (and
  to avoid adding a system-level DNS dependency to the backend), we use the
  same DoH endpoint the extension would use. This also ensures consistency:
  both the extension and backend query the same resolver.

Cloudflare DoH endpoint:
  GET https://1.1.1.1/dns-query?name=<qname>&type=<qtype>
  Accept: application/dns-json

  Type 16 = TXT record.
  The response JSON contains an "Answer" array; each element has a "data"
  field with the TXT record value, often wrapped in double quotes.
"""

import httpx

_DOH_URL = "https://1.1.1.1/dns-query"
_TXT_RECORD_TYPE = 16


async def query_txt_records(name: str) -> list[str]:
    """
    Fetch all TXT records for `name` via Cloudflare DoH.

    Returns a list of record strings with surrounding quotes stripped.
    Returns an empty list if the name doesn't exist (NXDOMAIN) or has no
    TXT records — callers should treat an empty list as "record not found",
    not as an error.

    Raises httpx.HTTPError on network failures so callers can decide how
    to handle connectivity issues independently of missing records.
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(
            _DOH_URL,
            params={"name": name, "type": "TXT"},
            headers={"Accept": "application/dns-json"},
            timeout=5.0,
        )
        response.raise_for_status()
        data = response.json()

    records = []
    for answer in data.get("Answer", []):
        if answer.get("type") == _TXT_RECORD_TYPE:
            # DNS TXT record values are returned as quoted strings by Cloudflare.
            # Strip the surrounding double quotes before returning.
            value = answer.get("data", "").strip('"')
            if value:
                records.append(value)

    return records
