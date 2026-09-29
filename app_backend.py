from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator

app = FastAPI(
    title="Multi-Domain Fraud and Risk Assessment API",
    version="1.0.0",
    description="Local PoC with mocked telecom/PTA-style infrastructure data.",
)

WEIGHTS = {
    "voip_line": 25,
    "leetspeak_detected": 20,
    "roman_urdu_scam_text": 35,
    "registration_velocity_high": 20,
}

ROMAN_URDU_PATTERNS = {
    "security_fee": [
        r"\bsecurity\s*fee\b",
        r"\bsecurity\s*(?:charges?|amount|payment)\b",
        r"\bsecurity\s*fee\s*do\b",
    ],
    "paisa": [
        r"\bpaisa\b",
        r"\bpaise\b",
        r"\brakam\b",
        r"\bpayment\b",
    ],
    "inam": [
        r"\bin['’]?am\b",
        r"\binam\b",
        r"\bprize\b",
        r"\binaam\b",
        r"\bjeet\b",
        r"\bmubarak\b",
    ],
    "job": [
        r"\bjob\b",
        r"\bnaukri\b",
        r"\bkamai\b",
        r"\bearning\b",
        r"\bwork\s*from\s*home\b",
    ],
    "account_threat": [
        r"\baccount\s*(?:band|block|blocked|suspend|suspended)\b",
        r"\bnumber\s*(?:band|block|blocked)\b",
        r"\bverification\s*fail\b",
        r"\bverify\s*(?:now|your)\b",
    ],
}

LEET_TRANSLATION = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
})

LEET_HINTS = re.compile(
    r"(?i)(?:\b[a-z]*\d[a-z]*\b|"
    r"f(?:3|e){1,2}|urg(?:3|e)nt|p[a@]is[a@]|"
    r"s[e3]cur[i1]ty|fr[e3]{2}|pr[i1]z[e3])"
)

PHONE_RE = re.compile(r"^\+?\d{10,15}$")


class RiskRequest(BaseModel):
    phone_number: str = Field(..., description="Phone number, e.g. +923001234567")
    message_text: str = Field(..., min_length=1, max_length=5000)
    carrier_type: str = Field(..., description="Carrier/line type selected by the user")

    @field_validator("phone_number")
    @classmethod
    def validate_phone(cls, value: str) -> str:
        cleaned = re.sub(r"[\s\-()]", "", value)
        if not PHONE_RE.fullmatch(cleaned):
            raise ValueError("Enter a valid phone number containing 10-15 digits.")
        return cleaned

    @field_validator("carrier_type")
    @classmethod
    def validate_carrier(cls, value: str) -> str:
        allowed = {"Mobile", "VOIP", "Fixed Line"}
        if value not in allowed:
            raise ValueError(f"carrier_type must be one of: {', '.join(sorted(allowed))}")
        return value


class RiskResponse(BaseModel):
    request: dict[str, Any]
    infrastructure: dict[str, Any]
    heuristic_analysis: dict[str, Any]
    risk_score: int
    risk_level: str
    flags: list[str]
    explainability: dict[str, Any]
    generated_at: str


def normalize_leetspeak(text: str) -> str:
    return text.translate(LEET_TRANSLATION)


def detect_leetspeak(text: str) -> dict[str, Any]:
    matches = LEET_HINTS.findall(text)
    normalized = normalize_leetspeak(text)

    # Require either an obvious suspicious token or a digit embedded in a word.
    detected = bool(matches) or bool(
        re.search(r"\b[a-zA-Z]+[013457@$][a-zA-Z]+\b", text)
    )

    return {
        "detected": detected,
        "matched_tokens": sorted(set(matches), key=str.lower),
        "normalized_text": normalized,
    }


def scan_scam_patterns(text: str) -> dict[str, Any]:
    normalized = normalize_leetspeak(text.lower())
    matched_categories: dict[str, list[str]] = {}

    for category, patterns in ROMAN_URDU_PATTERNS.items():
        hits = []
        for pattern in patterns:
            for match in re.finditer(pattern, normalized, flags=re.IGNORECASE):
                hits.append(match.group(0))
        if hits:
            matched_categories[category] = sorted(set(hits), key=str.lower)

    return {
        "matched": bool(matched_categories),
        "categories": matched_categories,
        "match_count": sum(len(v) for v in matched_categories.values()),
    }


def mock_registration_intelligence(phone_number: str) -> dict[str, Any]:
    """
    Deterministic local mock for telecom/PTA-style registration intelligence.
    No real carrier, PTA, SIM, subscriber, or external API is contacted.
    """
    digits = re.sub(r"\D", "", phone_number)
    seed = int(digits[-4:]) if digits else 0

    registrations_30d = 2 + (seed % 19)
    registrations_24h = seed % 8
    velocity_high = registrations_30d >= 15 or registrations_24h >= 5

    prefixes = {
        "030": "Jazz",
        "031": "Zong",
        "032": "Jazz",
        "033": "Ufone",
        "034": "Telenor",
        "035": "SCOM",
    }
    prefix = digits[:3]
    inferred_carrier = prefixes.get(prefix, "Unknown")

    return {
        "source": "MOCK_PTA_REGISTRATION_SERVICE",
        "subscriber_status": "active",
        "sim_age_days": 30 + (seed % 900),
        "registrations_last_30_days": registrations_30d,
        "registrations_last_24_hours": registrations_24h,
        "velocity_threshold_30d": 15,
        "velocity_threshold_24h": 5,
        "registration_velocity_high": velocity_high,
        "inferred_carrier_from_prefix": inferred_carrier,
    }


def mock_line_intelligence(phone_number: str, selected_carrier: str) -> dict[str, Any]:
    """
    Deterministic local mock for a carrier lookup.
    The user's selector is authoritative for the demo.
    """
    digits = re.sub(r"\D", "", phone_number)
    return {
        "source": "MOCK_CARRIER_LOOKUP",
        "phone_number_masked": (
            f"{digits[:4]}****{digits[-3:]}" if len(digits) >= 7 else "***"
        ),
        "line_type": selected_carrier,
        "is_voip": selected_carrier == "VOIP",
        "country_code": "+92" if digits.startswith("92") else "unknown",
    }


def risk_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def build_explainability(factors: dict[str, int], final_score: int) -> dict[str, Any]:
    contributions = []
    for key, points in factors.items():
        pct_of_final = round((points / final_score) * 100, 2) if final_score else 0.0
        contributions.append({
            "factor": key,
            "weight_points": WEIGHTS[key],
            "contribution_points": points,
            "contribution_percent_of_final_score": pct_of_final,
        })

    return {
        "method": "SHAP_STYLE_WEIGHTED_BREAKDOWN",
        "base_score": 0,
        "final_score": final_score,
        "total_possible_points": sum(WEIGHTS.values()),
        "contributions": contributions,
        "note": (
            "This is an explainability simulation for the PoC, not a true SHAP "
            "calculation from a trained ML model."
        ),
    }


def assess_risk(request: RiskRequest) -> RiskResponse:
    line_data = mock_line_intelligence(request.phone_number, request.carrier_type)
    registration_data = mock_registration_intelligence(request.phone_number)
    leet_data = detect_leetspeak(request.message_text)
    scam_data = scan_scam_patterns(request.message_text)

    factors = {
        "voip_line": WEIGHTS["voip_line"] if line_data["is_voip"] else 0,
        "leetspeak_detected": WEIGHTS["leetspeak_detected"] if leet_data["detected"] else 0,
        "roman_urdu_scam_text": (
            WEIGHTS["roman_urdu_scam_text"] if scam_data["matched"] else 0
        ),
        "registration_velocity_high": (
            WEIGHTS["registration_velocity_high"]
            if registration_data["registration_velocity_high"]
            else 0
        ),
    }

    final_score = min(100, sum(factors.values()))
    flags = []

    if factors["voip_line"]:
        flags.append("VOIP line type")
    if factors["leetspeak_detected"]:
        flags.append("Leetspeak/obfuscation detected")
    if factors["roman_urdu_scam_text"]:
        categories = ", ".join(scam_data["categories"].keys())
        flags.append(f"Roman Urdu/scam keywords detected: {categories}")
    if factors["registration_velocity_high"]:
        flags.append("High registration velocity")

    return RiskResponse(
        request={
            "phone_number": request.phone_number,
            "message_text": request.message_text,
            "carrier_type": request.carrier_type,
        },
        infrastructure={
            "carrier_lookup": line_data,
            "registration_intelligence": registration_data,
        },
        heuristic_analysis={
            "leetspeak": leet_data,
            "scam_pattern_scan": scam_data,
        },
        risk_score=final_score,
        risk_level=risk_level(final_score),
        flags=flags,
        explainability=build_explainability(factors, final_score),
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


# Placeholder for a future transformer-based NLP implementation.
def transformer_nlp_placeholder(text: str) -> dict[str, Any]:
    return {
        "model": "XLM-RoBERTa (future integration placeholder)",
        "status": "not_loaded_in_local_poc",
        "purpose": "Multilingual scam classification and semantic similarity",
        "input_length": len(text),
    }


# Placeholder for a future real SHAP implementation.
def shap_explainability_placeholder(features: dict[str, float]) -> dict[str, Any]:
    return {
        "library": "shap",
        "status": "placeholder",
        "features": features,
        "purpose": "Replace weighted simulation with SHAP values from a trained model",
    }


@app.get("/")
def root() -> dict[str, str]:
    return {
        "name": "Multi-Domain Fraud and Risk Assessment API",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy"}


@app.post("/api/v1/assess-risk", response_model=RiskResponse)
def assess_risk_endpoint(request: RiskRequest) -> RiskResponse:
    try:
        return assess_risk(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
