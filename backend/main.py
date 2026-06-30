from fastapi import FastAPI
from pydantic import BaseModel

from email_parser.verifier import verify_headers
from email_parser.models import ProtocolVerificationResult

app = FastAPI(title="PhishLens API")


class EmailHeader(BaseModel):
    name: str
    value: str


class EmailPayload(BaseModel):
    message_id: str
    headers: list[EmailHeader]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze/headers", response_model=ProtocolVerificationResult)
async def analyze_headers(payload: EmailPayload):
    """
    Accepts raw Gmail API headers and runs the full protocol verification
    pipeline: SPF, DKIM, DMARC — both fast-path (Authentication-Results)
    and live DNS-over-HTTPS lookups.
    """
    raw = [{"name": h.name, "value": h.value} for h in payload.headers]
    return await verify_headers(raw)
