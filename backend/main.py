from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="PhishLens API")


class EmailPayload(BaseModel):
    subject: str
    sender_name: str
    sender_email: str
    message_id: str


class AnalysisResult(BaseModel):
    verdict: str          # "safe" | "suspicious" | "phishing"
    confidence: float     # 0.0 – 1.0
    reason: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalysisResult)
def analyze(payload: EmailPayload):
    # Stub: real ML model plugs in here
    return AnalysisResult(
        verdict="safe",
        confidence=0.0,
        reason="Model not yet implemented.",
    )
