from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, List, Dict, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator


app = FastAPI(
    title="Multi-Domain Fraud and Risk Assessment API",
    version="2.0.0",
    description=(
        "SSUET FYP Advanced PoC with Graph Fraud-Rings, "
        "Behavioral Analytics, and Telecom Metadata."
    ),
)


# =====================================================================
#                         RISK WEIGHTS
# =====================================================================

WEIGHTS = {
    "voip_line": 20,
    "leetspeak_detected": 15,
    "roman_urdu_scam_text": 25,
    "registration_velocity_high": 15,
    "fraud_ring_linked": 15,
    "behavioral_anomaly": 10,
}


# =====================================================================
#                    ROMAN URDU SCAM PATTERNS
# =====================================================================

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


# =====================================================================
#                         LEETSPEAK ENGINE
# =====================================================================

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
    r"f(?:3|e){1,2}|"
    r"urg(?:3|e)nt|"
    r"p[a@]is[a@]|"
    r"s[e3]cur[i1]ty|"
    r"fr[e3]{2}|"
    r"pr[i1]z[e3])"
)


PHONE_RE = re.compile(r"^\+?\d{10,15}$")


# =====================================================================
#                   IN-MEMORY GRAPH DATABASE
# =====================================================================

FRAUD_GRAPH_DB: List[Dict[str, Any]] = []


# =====================================================================
#                         REQUEST MODEL
# =====================================================================

class RiskRequest(BaseModel):
    phone_number: str = Field(
        ...,
        description="Phone number, e.g. +923001234567",
    )

    message_text: str = Field(
        ...,
        min_length=1,
        max_length=5000,
    )

    carrier_type: str = Field(
        ...,
        description="Carrier/line type selected by the user",
    )

    ip_address: Optional[str] = Field(
        "192.168.1.1",
        description="Sender IP or infrastructure routing tracking",
    )

    extracted_domain: Optional[str] = Field(
        "unknown",
        description="Suspicious URL link extracted from advertisement",
    )

    logo_mismatch_detected: Optional[bool] = Field(
        False,
        description="Computer Vision profile photo verification flag",
    )

    @field_validator("phone_number")
    @classmethod
    def validate_phone(cls, value: str) -> str:
        cleaned = re.sub(r"[\s\-()]", "", value)

        if not PHONE_RE.fullmatch(cleaned):
            raise ValueError(
                "Enter a valid phone number containing 10-15 digits."
            )

        return cleaned

    @field_validator("carrier_type")
    @classmethod
    def validate_carrier(cls, value: str) -> str:
        allowed = {"Mobile", "VOIP", "Fixed Line"}

        if value not in allowed:
            raise ValueError(
                f"carrier_type must be one of: {', '.join(sorted(allowed))}"
            )

        return value


# =====================================================================
#                         RESPONSE MODEL
# =====================================================================

class RiskResponse(BaseModel):
    request: dict[str, Any]
    infrastructure: dict[str, Any]
    heuristic_analysis: dict[str, Any]
    cross_domain_graph: dict[str, Any]
    anomaly_detection: dict[str, Any]

    risk_score: int
    risk_level: str

    flags: list[str]

    explainability: dict[str, Any]

    generated_at: str


# =====================================================================
#                    TEXT PROCESSING FUNCTIONS
# =====================================================================

def normalize_leetspeak(text: str) -> str:
    return text.translate(LEET_TRANSLATION)


def detect_leetspeak(text: str) -> dict[str, Any]:
    matches = LEET_HINTS.findall(text)

    normalized = normalize_leetspeak(text)

    detected = bool(matches) or bool(
        re.search(
            r"\b[a-zA-Z]+[013457@$][a-zA-Z]+\b",
            text
        )
    )

    return {
        "detected": detected,
        "matched_tokens": sorted(
            set(matches),
            key=str.lower
        ),
        "normalized_text": normalized,
    }


def scan_scam_patterns(text: str) -> dict[str, Any]:
    normalized = normalize_leetspeak(text.lower())

    matched_categories: dict[str, list[str]] = {}

    for category, patterns in ROMAN_URDU_PATTERNS.items():

        hits = []

        for pattern in patterns:

            for match in re.finditer(
                pattern,
                normalized,
                flags=re.IGNORECASE
            ):
                hits.append(match.group(0))

        if hits:
            matched_categories[category] = sorted(
                set(hits),
                key=str.lower
            )

    return {
        "matched": bool(matched_categories),
        "categories": matched_categories,
        "match_count": sum(
            len(v)
            for v in matched_categories.values()
        ),
    }


# =====================================================================
#                    REGISTRATION INTELLIGENCE
# =====================================================================

def mock_registration_intelligence(
    phone_number: str
) -> dict[str, Any]:

    digits = re.sub(r"\D", "", phone_number)

    seed = int(digits[-4:]) if digits else 0

    registrations_30d = 2 + (seed % 19)
    registrations_24h = seed % 8

    velocity_high = (
        registrations_30d >= 15
        or registrations_24h >= 5
    )

    prefixes = {
        "030": "Jazz",
        "031": "Zong",
        "032": "Jazz",
        "033": "Ufone",
        "034": "Telenor",
        "035": "SCOM",
    }

    prefix = digits[:3]

    inferred_carrier = prefixes.get(
        prefix,
        "Unknown"
    )

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


# =====================================================================
#                    CROSS-DOMAIN GRAPH ENGINE
# =====================================================================

def analyze_cross_domain_graph(
    phone: str,
    domain: Optional[str],
    ip: Optional[str],
) -> dict[str, Any]:

    linked_cases = []

    shared_infrastructure = []

    for case in FRAUD_GRAPH_DB:

        has_link = False

        if case["phone"] == phone:
            has_link = True
            shared_infrastructure.append(
                "phone_number"
            )

        if (
            domain
            and domain != "unknown"
            and case["domain"] == domain
        ):
            has_link = True
            shared_infrastructure.append(
                "shared_url_domain"
            )

        if (
            ip
            and ip != "192.168.1.1"
            and case["ip"] == ip
        ):
            has_link = True
            shared_infrastructure.append(
                "infrastructure_ip"
            )

        if has_link:
            linked_cases.append(case["id"])

    unique_edges = sorted(
        list(set(shared_infrastructure))
    )

    return {
        "fraud_ring_detected": len(linked_cases) > 0,
        "linked_historical_case_ids": linked_cases,
        "shared_infrastructure_edges": unique_edges,
        "graph_node_count": len(FRAUD_GRAPH_DB) + 1,
    }


# =====================================================================
#                    BEHAVIORAL ANALYSIS
# =====================================================================

def analyze_behavioral_patterns() -> dict[str, Any]:

    current_hour = datetime.now(
        timezone.utc
    ).hour

    is_suspicious_window = (
        2 <= current_hour <= 5
    )

    return {
        "request_timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat(),

        "bot_automation_probability": (
            0.85
            if is_suspicious_window
            else 0.12
        ),

        "suspicious_time_window":
            is_suspicious_window,
    }


# =====================================================================
#                    ANOMALY ENGINE
# =====================================================================

def analyze_unsupervised_anomalies(
    request: RiskRequest
) -> dict[str, Any]:

    is_outlier = (
        request.carrier_type == "VOIP"
        and request.logo_mismatch_detected
    )

    anomaly_score = (
        0.91
        if is_outlier
        else 0.18
    )

    return {
        "engine": "IsolationForest_Simulation_Layer",
        "anomaly_score": anomaly_score,
        "outlier_status": anomaly_score > 0.70,
    }


# =====================================================================
#                         RISK LEVEL
# =====================================================================

def risk_level(score: int) -> str:

    if score >= 75:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= 25:
        return "MEDIUM"

    return "LOW"


# =====================================================================
#                    EXPLAINABILITY ENGINE
# =====================================================================

def build_explainability(
    factors: dict[str, int],
    final_score: int,
) -> dict[str, Any]:

    contributions = []

    for key, points in factors.items():

        pct_of_final = (
            round(
                (points / final_score) * 100,
                2
            )
            if final_score
            else 0.0
        )

        contributions.append({
            "factor": key,
            "weight_points": WEIGHTS[key],
            "contribution_points": points,
            "contribution_percent_of_final_score":
                pct_of_final,
        })

    return {
        "method":
            "SHAP_STYLE_WEIGHTED_BREAKDOWN",

        "base_score": 0,

        "final_score": final_score,

        "total_possible_points":
            sum(WEIGHTS.values()),

        "contributions":
            contributions,

        "note":
            "SHAP-style explainability mapping "
            "structural graph nodes and textual features.",
    }


# =====================================================================
#                       MAIN RISK ENGINE
# =====================================================================

def assess_risk(
    request: RiskRequest
) -> RiskResponse:

    registration_data = (
        mock_registration_intelligence(
            request.phone_number
        )
    )

    leet_data = detect_leetspeak(
        request.message_text
    )

    scam_data = scan_scam_patterns(
        request.message_text
    )

    graph_data = analyze_cross_domain_graph(
        request.phone_number,
        request.extracted_domain,
        request.ip_address,
    )

    behavior_data = analyze_behavioral_patterns()

    anomaly_data = analyze_unsupervised_anomalies(
        request
    )

    # -------------------------------------------------------------
    #                     RISK FACTORS
    # -------------------------------------------------------------

    factors = {

        "voip_line":
            WEIGHTS["voip_line"]
            if request.carrier_type == "VOIP"
            else 0,

        "leetspeak_detected":
            WEIGHTS["leetspeak_detected"]
            if leet_data["detected"]
            else 0,

        "roman_urdu_scam_text":
            WEIGHTS["roman_urdu_scam_text"]
            if scam_data["matched"]
            else 0,

        "registration_velocity_high":
            WEIGHTS["registration_velocity_high"]
            if registration_data[
                "registration_velocity_high"
            ]
            else 0,

        "fraud_ring_linked":
            WEIGHTS["fraud_ring_linked"]
            if graph_data["fraud_ring_detected"]
            else 0,

        "behavioral_anomaly":
            WEIGHTS["behavioral_anomaly"]
            if (
                behavior_data[
                    "suspicious_time_window"
                ]
                or request.logo_mismatch_detected
            )
            else 0,
    }

    # -------------------------------------------------------------
    #                       FINAL SCORE
    # -------------------------------------------------------------

    final_score = min(
        100,
        sum(factors.values())
    )

    # -------------------------------------------------------------
    #                         FLAGS
    # -------------------------------------------------------------

    flags = []

    if factors["voip_line"]:
        flags.append(
            "VOIP line type infrastructure detected"
        )

    if factors["leetspeak_detected"]:
        flags.append(
            "Leetspeak/Obfuscation signature detected"
        )

    if factors["roman_urdu_scam_text"]:

        categories = ", ".join(
            scam_data["categories"].keys()
        )

        flags.append(
            f"Roman Urdu scam keywords matched: "
            f"{categories}"
        )

    if factors["registration_velocity_high"]:
        flags.append(
            "High telemetry registration velocity flagged"
        )

    if factors["fraud_ring_linked"]:

        flags.append(
            "Cross-Domain Fraud-Ring Linked via: "
            + ", ".join(
                graph_data[
                    "shared_infrastructure_edges"
                ]
            )
        )

    if request.logo_mismatch_detected:
        flags.append(
            "Computer Vision: Corporate Logo "
            "Mismatch / Stolen Identity"
        )

    # -------------------------------------------------------------
    #                 ADD CURRENT CASE TO GRAPH
    # -------------------------------------------------------------

    case_id = (
        f"CASE_{len(FRAUD_GRAPH_DB) + 1001}"
    )

    FRAUD_GRAPH_DB.append({
        "id": case_id,
        "phone": request.phone_number,
        "domain":
            request.extracted_domain
            or "unknown",
        "ip":
            request.ip_address
            or "192.168.1.1",
    })

    # -------------------------------------------------------------
    #                       RESPONSE
    # -------------------------------------------------------------

    return RiskResponse(

        request={
            "phone_number":
                request.phone_number,

            "message_text":
                request.message_text,

            "carrier_type":
                request.carrier_type,

            "ip_address":
                request.ip_address,

            "extracted_domain":
                request.extracted_domain,
        },

        infrastructure={

            "carrier_lookup": {
                "line_type":
                    request.carrier_type,

                "is_voip":
                    request.carrier_type == "VOIP",
            },

            "registration_intelligence":
                registration_data,
        },

        heuristic_analysis={

            "leetspeak":
                leet_data,

            "scam_pattern_scan":
                scam_data,
        },

        cross_domain_graph=
            graph_data,

        anomaly_detection=
            anomaly_data,

        risk_score=
            final_score,

        risk_level=
            risk_level(final_score),

        flags=
            flags,

        explainability=
            build_explainability(
                factors,
                final_score
            ),

        generated_at=
            datetime.now(
                timezone.utc
            ).isoformat(),
    )


# =====================================================================
#                         API ROUTES
# =====================================================================

@app.get("/")
def root() -> dict[str, str]:

    return {
        "name":
            "SSUET Multi-Domain Fraud and Risk API Engine",

        "status":
            "running",

        "docs":
            "/docs",
    }


@app.get("/health")
def health() -> dict[str, str]:

    return {
        "status": "healthy"
    }


@app.post(
    "/api/v1/assess-risk",
    response_model=RiskResponse
)
def assess_risk_endpoint(
    request: RiskRequest
) -> RiskResponse:

    try:

        return assess_risk(request)

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc)
        ) from exc
