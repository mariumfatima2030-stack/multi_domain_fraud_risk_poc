from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional

import streamlit as st
import plotly.graph_objects as go


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="SSUET Advanced Fraud Dashboard",
    page_icon="🛡️",
    layout="wide",
)


# ============================================================
# RISK WEIGHTS
# ============================================================

WEIGHTS = {
    "voip_line": 20,
    "leetspeak_detected": 15,
    "roman_urdu_scam_text": 25,
    "registration_velocity_high": 15,
    "fraud_ring_linked": 15,
    "behavioral_anomaly": 10,
}


# ============================================================
# ROMAN URDU SCAM PATTERNS
# ============================================================

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


# ============================================================
# LEETSPEAK ENGINE
# ============================================================

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


# ============================================================
# IN-MEMORY FRAUD GRAPH
# ============================================================

FRAUD_GRAPH_DB: list[dict[str, Any]] = []


# ============================================================
# TEXT FUNCTIONS
# ============================================================

def normalize_leetspeak(text: str) -> str:
    return text.translate(LEET_TRANSLATION)


def detect_leetspeak(text: str) -> dict[str, Any]:
    matches = LEET_HINTS.findall(text)

    normalized = normalize_leetspeak(text)

    detected = bool(matches) or bool(
        re.search(
            r"\b[a-zA-Z]+[013457@$][a-zA-Z]+\b",
            text,
        )
    )

    return {
        "detected": detected,
        "matched_tokens": sorted(
            set(matches),
            key=str.lower,
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
                flags=re.IGNORECASE,
            ):
                hits.append(match.group(0))

        if hits:
            matched_categories[category] = sorted(
                set(hits),
                key=str.lower,
            )

    return {
        "matched": bool(matched_categories),
        "categories": matched_categories,
        "match_count": sum(
            len(values)
            for values in matched_categories.values()
        ),
    }


# ============================================================
# REGISTRATION INTELLIGENCE
# ============================================================

def mock_registration_intelligence(
    phone_number: str,
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
        "Unknown",
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


# ============================================================
# CROSS-DOMAIN GRAPH
# ============================================================

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
            shared_infrastructure.append("phone_number")

        if (
            domain
            and domain != "unknown"
            and case["domain"] == domain
        ):
            has_link = True
            shared_infrastructure.append("shared_url_domain")

        if (
            ip
            and ip != "192.168.1.1"
            and case["ip"] == ip
        ):
            has_link = True
            shared_infrastructure.append("infrastructure_ip")

        if has_link:
            linked_cases.append(case["id"])

    unique_edges = sorted(
        set(shared_infrastructure)
    )

    return {
        "fraud_ring_detected": len(linked_cases) > 0,
        "linked_historical_case_ids": linked_cases,
        "shared_infrastructure_edges": unique_edges,
        "graph_node_count": len(FRAUD_GRAPH_DB) + 1,
    }


# ============================================================
# BEHAVIORAL ANALYSIS
# ============================================================

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


# ============================================================
# ANOMALY ENGINE
# ============================================================

def analyze_unsupervised_anomalies(
    carrier_type: str,
    logo_mismatch_detected: bool,
) -> dict[str, Any]:

    is_outlier = (
        carrier_type == "VOIP"
        and logo_mismatch_detected
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


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score: int) -> str:

    if score >= 75:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= 25:
        return "MEDIUM"

    return "LOW"


# ============================================================
# EXPLAINABILITY
# ============================================================

def build_explainability(
    factors: dict[str, int],
    final_score: int,
) -> dict[str, Any]:

    contributions = []

    for key, points in factors.items():

        percentage = (
            round(
                (points / final_score) * 100,
                2,
            )
            if final_score
            else 0.0
        )

        contributions.append({
            "factor": key,
            "weight_points": WEIGHTS[key],
            "contribution_points": points,
            "contribution_percent_of_final_score":
                percentage,
        })

    return {
        "method":
            "SHAP_STYLE_WEIGHTED_BREAKDOWN",

        "base_score": 0,

        "final_score": final_score,

        "total_possible_points":
            sum(WEIGHTS.values()),

        "contributions": contributions,

        "note":
            "SHAP-style explainability mapping "
            "structural graph nodes and textual features.",
    }


# ============================================================
# MAIN RISK ENGINE
# ============================================================

def assess_risk(
    phone_number: str,
    message_text: str,
    carrier_type: str,
    ip_address: str,
    extracted_domain: str,
    logo_mismatch_detected: bool,
) -> dict[str, Any]:

    # -----------------------------
    # Registration intelligence
    # -----------------------------

    registration_data = (
        mock_registration_intelligence(
            phone_number
        )
    )

    # -----------------------------
    # Text analysis
    # -----------------------------

    leet_data = detect_leetspeak(
        message_text
    )

    scam_data = scan_scam_patterns(
        message_text
    )

    # -----------------------------
    # Graph
    # -----------------------------

    graph_data = analyze_cross_domain_graph(
        phone_number,
        extracted_domain,
        ip_address,
    )

    # -----------------------------
    # Behavioral analysis
    # -----------------------------

    behavior_data = (
        analyze_behavioral_patterns()
    )

    # -----------------------------
    # Anomaly
    # -----------------------------

    anomaly_data = (
        analyze_unsupervised_anomalies(
            carrier_type,
            logo_mismatch_detected,
        )
    )

    # -----------------------------
    # Risk factors
    # -----------------------------

    factors = {

        "voip_line":
            WEIGHTS["voip_line"]
            if carrier_type == "VOIP"
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
            if graph_data[
                "fraud_ring_detected"
            ]
            else 0,

        "behavioral_anomaly":
            WEIGHTS["behavioral_anomaly"]
            if (
                behavior_data[
                    "suspicious_time_window"
                ]
                or logo_mismatch_detected
            )
            else 0,
    }

    # -----------------------------
    # Final score
    # -----------------------------

    final_score = min(
        100,
        sum(factors.values()),
    )

    # -----------------------------
    # Flags
    # -----------------------------

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

    if logo_mismatch_detected:
        flags.append(
            "Computer Vision: Corporate Logo "
            "Mismatch / Stolen Identity"
        )

    # -----------------------------
    # Add current case to graph
    # -----------------------------

    case_id = (
        f"CASE_{len(FRAUD_GRAPH_DB) + 1001}"
    )

    FRAUD_GRAPH_DB.append({
        "id": case_id,
        "phone": phone_number,
        "domain": extracted_domain or "unknown",
        "ip": ip_address or "192.168.1.1",
    })

    # -----------------------------
    # Final response
    # -----------------------------

    return {

        "request": {
            "phone_number": phone_number,
            "message_text": message_text,
            "carrier_type": carrier_type,
            "ip_address": ip_address,
            "extracted_domain": extracted_domain,
        },

        "infrastructure": {

            "carrier_lookup": {
                "line_type": carrier_type,
                "is_voip": carrier_type == "VOIP",
            },

            "registration_intelligence":
                registration_data,
        },

        "heuristic_analysis": {

            "leetspeak":
                leet_data,

            "scam_pattern_scan":
                scam_data,
        },

        "cross_domain_graph":
            graph_data,

        "anomaly_detection":
            anomaly_data,

        "risk_score":
            final_score,

        "risk_level":
            get_risk_level(final_score),

        "flags":
            flags,

        "explainability":
            build_explainability(
                factors,
                final_score,
            ),

        "generated_at":
            datetime.now(
                timezone.utc
            ).isoformat(),
    }


# ============================================================
# SESSION STATE
# ============================================================

if "advanced_assessment" not in st.session_state:
    st.session_state["advanced_assessment"] = None


# ============================================================
# HEADER
# ============================================================

st.title(
    "🛡️ Multi-Domain Fraud & Risk Assessment"
)

st.caption(
    "Advanced FYP PoC — Real-time Graph Infrastructure "
    "Layer & Unsupervised Outlier Analytics"
)

st.info(
    "Infrastructure data is evaluated through the fraud-risk "
    "assessment engine. Registration intelligence shown in "
    "this PoC is simulated/mock data for academic evaluation."
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.header(
        "⚡ Assessment Input Parameters"
    )

    phone_number = st.text_input(
        "Phone Number",
        value="+923001234567",
        placeholder="+923001234567",
        help="Enter a phone number containing 10–15 digits.",
    )

    message_text = st.text_area(
        "Ad / Message Text",
        value=(
            "Urg3nt! Ap ko in'am mila hai. "
            "Security fee 5000 paisa jama karain."
        ),
        height=130,
        help=(
            "Supports Roman Urdu scam-pattern "
            "analysis and leetspeak detection."
        ),
    )

    carrier_type = st.selectbox(
        "Carrier / Line Type",
        [
            "Mobile",
            "VOIP",
            "Fixed Line",
        ],
        index=1,
    )

    st.subheader(
        "🌐 Network Telemetry"
    )

    ip_address = st.text_input(
        "Infrastructure IP Vector",
        value="192.168.43.10",
    )

    extracted_domain = st.text_input(
        "Extracted Link URL Domain",
        value="bisp-reward-funds.com",
    )

    st.subheader(
        "📸 Computer Vision Emulation"
    )

    logo_mismatch = st.checkbox(
        "Flag Corporate Logo Mismatch (Stolen Identity)",
        value=False,
        help=(
            "Simulation of a computer-vision identity "
            "mismatch signal."
        ),
    )

    st.divider()

    assess = st.button(
        "🔍 Run Advanced Risk Analysis",
        type="primary",
        use_container_width=True,
    )

    clear = st.button(
        "🗑️ Clear Assessment",
        use_container_width=True,
    )


# ============================================================
# CLEAR
# ============================================================

if clear:

    st.session_state[
        "advanced_assessment"
    ] = None

    st.rerun()


# ============================================================
# RUN ANALYSIS
# ============================================================

if assess:

    cleaned_phone = re.sub(
        r"[\s\-()]",
        "",
        phone_number,
    )

    if not PHONE_RE.fullmatch(cleaned_phone):

        st.error(
            "❌ Enter a valid phone number containing "
            "10–15 digits."
        )

        st.stop()

    if not message_text.strip():

        st.error(
            "❌ Message text cannot be empty."
        )

        st.stop()

    with st.spinner(
        "🔄 Running advanced fraud-risk analysis..."
    ):

        result = assess_risk(
            phone_number=cleaned_phone,
            message_text=message_text,
            carrier_type=carrier_type,
            ip_address=ip_address,
            extracted_domain=extracted_domain,
            logo_mismatch_detected=logo_mismatch,
        )

    st.session_state[
        "advanced_assessment"
    ] = result

    st.success(
        "✅ Risk assessment completed successfully."
    )


# ============================================================
# RESULT
# ============================================================

result = st.session_state.get(
    "advanced_assessment"
)


# ============================================================
# INITIAL SCREEN
# ============================================================

if not result:

    st.subheader(
        "SSUET Unified Scoring Architecture Matrix"
    )

    st.markdown(
        """
### Risk Assessment Factors

- **VOIP Base Line Deployment Routing:** +20 Points
- **Leetspeak / Obfuscation Character Matches:** +15 Points
- **Roman Urdu Text Patterns & Key Match:** +25 Points
- **High Network Registration Telemetry Velocity:** +15 Points
- **Cross-Domain Fraud-Ring Connected Links:** +15 Points
- **Behavioral Outlier Time Anomalies:** +10 Points

**Maximum Unified Score: 100 Points**
        """
    )

    st.divider()

    st.info(
        "Enter assessment parameters from the sidebar and "
        "click **Run Advanced Risk Analysis**."
    )

    st.stop()


# ============================================================
# RESULT DATA
# ============================================================

score = int(
    result.get("risk_score", 0)
)

level = result.get(
    "risk_level",
    "UNKNOWN",
)

flags = result.get(
    "flags",
    [],
)

graph_data = result.get(
    "cross_domain_graph",
    {},
)

anomaly = result.get(
    "anomaly_detection",
    {},
)

explainability = result.get(
    "explainability",
    {},
)

heuristic = result.get(
    "heuristic_analysis",
    {},
)

scam_scan = heuristic.get(
    "scam_pattern_scan",
    {},
)

leet_scan = heuristic.get(
    "leetspeak",
    {},
)


# ============================================================
# SCORE HEADER
# ============================================================

st.subheader(
    "🎯 Unified Fraud Risk Assessment"
)

metric1, metric2, metric3 = st.columns(3)

with metric1:
    st.metric(
        "Risk Score",
        f"{score}/100",
    )

with metric2:
    st.metric(
        "Risk Level",
        level,
    )

with metric3:
    st.metric(
        "Graph Nodes",
        graph_data.get(
            "graph_node_count",
            0,
        ),
    )

st.divider()


# ============================================================
# RISK GAUGE
# ============================================================

left, right = st.columns(
    [1, 1.7]
)

with left:

    st.subheader(
        "📊 Unified Structural Risk Score"
    )

    if score >= 75:
        gauge_color = "red"
    elif score >= 50:
        gauge_color = "orange"
    elif score >= 25:
        gauge_color = "gold"
    else:
        gauge_color = "green"

    gauge = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,

            number={
                "suffix": "/100",
                "font": {
                    "size": 42,
                },
            },

            title={
                "text": (
                    f"Status Evaluated: "
                    f"<b>{level}</b>"
                ),
            },

            gauge={
                "axis": {
                    "range": [0, 100],
                    "tickwidth": 1,
                    "tickcolor": "darkgray",
                },

                "bar": {
                    "thickness": 0.35,
                    "color": gauge_color,
                },

                "steps": [
                    {
                        "range": [0, 25],
                        "color": "lightgreen",
                    },
                    {
                        "range": [25, 50],
                        "color": "lightyellow",
                    },
                    {
                        "range": [50, 75],
                        "color": "orange",
                    },
                    {
                        "range": [75, 100],
                        "color": "lightcoral",
                    },
                ],

                "threshold": {
                    "line": {
                        "color": "black",
                        "width": 4,
                    },

                    "thickness": 0.75,
                    "value": score,
                },
            },
        )
    )

    gauge.update_layout(
        height=300,
        margin=dict(
            l=20,
            r=20,
            t=60,
            b=20,
        ),
    )

    st.plotly_chart(
        gauge,
        use_container_width=True,
    )

    st.metric(
        "Unified Assessment Level",
        level,
    )

    st.progress(
        min(
            max(score / 100, 0.0),
            1.0,
        )
    )


# ============================================================
# FLAGS
# ============================================================

with right:

    st.subheader(
        "🚩 Active High-Risk Infrastructure Flags"
    )

    if flags:

        for flag in flags:

            st.error(
                f"⚠️ {flag}"
            )

    else:

        st.success(
            "✅ Clean Signature: Structural parameters "
            "fall inside trusted limits."
        )


# ============================================================
# GRAPH + ANOMALY
# ============================================================

st.divider()

col1, col2 = st.columns(2)


# ============================================================
# GRAPH NETWORK
# ============================================================

with col1:

    st.subheader(
        "🕸️ Cross-Domain Graph Network Links"
    )

    fraud_ring_detected = graph_data.get(
        "fraud_ring_detected",
        False,
    )

    linked_cases = graph_data.get(
        "linked_historical_case_ids",
        [],
    )

    shared_edges = graph_data.get(
        "shared_infrastructure_edges",
        [],
    )

    if fraud_ring_detected:

        st.warning(
            "⚠️ Organized Fraud-Ring Signature Detected"
        )

        st.write(
            "Linked historical cases:",
            len(linked_cases),
        )

        if shared_edges:

            st.write(
                "Overlapping Threat Vectors:"
            )

            for edge in shared_edges:
                st.code(edge)

        if linked_cases:

            st.write(
                "Linked Fraud Chain Cases:"
            )

            for case_id in linked_cases:
                st.write(
                    f"🔗 {case_id}"
                )

    else:

        st.success(
            "✅ Isolation Check Passed: Node metrics "
            "do not correlate with existing adversarial "
            "infrastructure."
        )

    st.metric(
        "Active Fraud Graph Database Tracking Nodes",
        graph_data.get(
            "graph_node_count",
            0,
        ),
    )


# ============================================================
# ANOMALY
# ============================================================

with col2:

    st.subheader(
        "🤖 Unsupervised Outlier Profiling"
    )

    engine = anomaly.get(
        "engine",
        "Unknown",
    )

    anomaly_score = float(
        anomaly.get(
            "anomaly_score",
            0.0,
        )
    )

    outlier_status = anomaly.get(
        "outlier_status",
        False,
    )

    st.write(
        "Statistical Processing Pipeline Engine:",
        engine,
    )

    st.metric(
        "Anomaly Score",
        f"{anomaly_score:.2f}",
    )

    st.progress(
        min(
            max(anomaly_score, 0.0),
            1.0,
        )
    )

    st.caption(
        f"Density Outlier Index: "
        f"{anomaly_score:.2f} "
        f"(Structural Threshold: 0.70)"
    )

    if outlier_status:

        st.error(
            "🚨 Anomalous Behavior Profile Flagged: "
            "Multi-signature misalignment detected."
        )

    else:

        st.info(
            "ℹ️ Transaction signature profile is "
            "inside the simulated normal distribution."
        )


# ============================================================
# EXPLAINABILITY + HEURISTICS
# ============================================================

st.divider()

col3, col4 = st.columns(2)


with col3:

    st.subheader(
        "📊 Explainability Attribute Attribution"
    )

    contributions = explainability.get(
        "contributions",
        [],
    )

    if contributions:

        for item in contributions:

            factor = item.get(
                "factor",
                "unknown",
            )

            factor_display = (
                factor
                .replace("_", " ")
                .title()
            )

            contribution_points = int(
                item.get(
                    "contribution_points",
                    0,
                )
            )

            contribution_percent = float(
                item.get(
                    "contribution_percent_of_final_score",
                    0,
                )
            )

            st.write(
                f"**{factor_display}** — "
                f"+{contribution_points} Engine Points"
            )

            st.progress(
                min(
                    max(
                        contribution_points / 100,
                        0.0,
                    ),
                    1.0,
                )
            )

            st.caption(
                f"Accounts for "
                f"{contribution_percent}% "
                f"of final structural assessment."
            )

    else:

        st.info(
            "No explainability contribution data returned."
        )


# ============================================================
# HEURISTIC ANALYSIS
# ============================================================

with col4:

    st.subheader(
        "🔍 Localized Heuristic Parsing Findings"
    )

    leet_detected = leet_scan.get(
        "detected",
        False,
    )

    matched_tokens = leet_scan.get(
        "matched_tokens",
        [],
    )

    scam_matched = scam_scan.get(
        "matched",
        False,
    )

    categories = scam_scan.get(
        "categories",
        {},
    )

    st.write(
        "Obfuscation Mask Matching:",
        (
            "True Signature Found"
            if leet_detected
            else "Clean Signatures Only"
        ),
    )

    if matched_tokens:

        st.write(
            "Identified Tokens:",
            ", ".join(matched_tokens),
        )

    st.write(
        "Roman Urdu Script Token Intersection:",
        (
            "Scam Intercepted"
            if scam_matched
            else "Normal Conversion Profile"
        ),
    )

    if categories:

        st.write(
            "Detected Scam Categories:"
        )

        for category, matches in categories.items():

            st.write(
                f"**{category.replace('_', ' ').title()}**"
            )

            for match in matches:
                st.code(match)


# ============================================================
# REQUEST INFORMATION
# ============================================================

st.divider()

st.subheader(
    "📡 Assessment Request Information"
)

request_data = result.get(
    "request",
    {},
)

req1, req2, req3 = st.columns(3)

with req1:

    st.write(
        "**Phone Number**"
    )

    st.code(
        request_data.get(
            "phone_number",
            "N/A",
        )
    )

with req2:

    st.write(
        "**Carrier / Line Type**"
    )

    st.code(
        request_data.get(
            "carrier_type",
            "N/A",
        )
    )

with req3:

    st.write(
        "**Infrastructure IP**"
    )

    st.code(
        request_data.get(
            "ip_address",
            "N/A",
        )
    )


# ============================================================
# ADVANCED JSON
# ============================================================

st.divider()

with st.expander(
    "🛠️ Advanced Assessment Metadata JSON"
):

    st.json(result)


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "SSUET Computer Engineering — Final Year Project "
    "Advanced Proof of Concept"
)