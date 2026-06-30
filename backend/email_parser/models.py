from enum import Enum
from pydantic import BaseModel


class AuthStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    UNKNOWN = "unknown"


class DMARCPolicy(str, Enum):
    NONE = "none"
    QUARANTINE = "quarantine"
    REJECT = "reject"
    UNKNOWN = "unknown"


class SPFResult(BaseModel):
    status: AuthStatus = AuthStatus.UNKNOWN
    domain: str | None = None
    detail: str | None = None


class DKIMResult(BaseModel):
    status: AuthStatus = AuthStatus.UNKNOWN
    signing_domain: str | None = None   # d= tag: domain that holds the public key
    selector: str | None = None         # s= tag: which key pair to use
    aligns_with_from: bool = False       # does signing_domain match the From: domain?
    detail: str | None = None


class DMARCResult(BaseModel):
    status: AuthStatus = AuthStatus.UNKNOWN
    reported_policy: DMARCPolicy = DMARCPolicy.UNKNOWN  # from Authentication-Results comment
    published_policy: DMARCPolicy = DMARCPolicy.UNKNOWN  # from live _dmarc DNS lookup
    detail: str | None = None


class ProtocolVerificationResult(BaseModel):
    from_domain: str | None = None
    spf: SPFResult
    dkim: DKIMResult
    dmarc: DMARCResult
    alignment_pass: bool = False
    risk_level: str = "unknown"  # "low" | "medium" | "high"
