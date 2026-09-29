from __future__ import annotations

import re
import streamlit as st
import plotly.graph_objects as go
from datetime import datetime, timezone
from typing import Any, List, Dict, Optional

# Page Configuration
st.set_page_config(
    page_title="SSUET Advanced Fraud Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# Initialize Session State for In-Memory Graph Network (Section 8)
if "FRAUD_GRAPH_DB" not in st.session_state:
    st.session_state["FRAUD_GRAPH_DB"] = []

# =====================================================================
#             FASTAPI ENGINE MERGED (SERVERLESS IMPLEMENTATION)
# =====================================================================

WEIGHTS = {
    "voip_line": 20,
    "leetspeak_detected": 15,
    "roman_urdu_scam_text": 25,
    "registration_velocity_high": 15,
    "fraud_ring_linked": 15,
    "behavioral_anomaly": 10,
}

ROMAN_URDU_PATTERNS = {
    "security_fee": [r"\bsecurity\s*fee\b", r"\bsecurity\s*(?:charges?|amount|payment)\b", r"\bsecurity\s*fee\s*do\b"],
    "paisa": [r"\bpaisa\b", r"\bpaise\b", r"\brakam\b", r"\bpayment\b"],
    "inam": [r"\bin['’]?am\b", r"\binam\b", r"\bprize\b", r"\binaam\b", r"\bjeet\b", r"\bmubarak\b"],
    "job": [r"\bjob\b", r"\bnaukri\b", r"\bkamai\b", r"\bearning\b", r"\bwork\s*from\s*home\b"],
    "account_threat": [
        r"\baccount\s*(?:band|block|blocked|suspend|suspended)\b",
        r"\bnumber\s*(?:band|block|blocked)\b",
        r"\bverification\s*fail\b",
        r"\bverify\s*(?:now|your)\b"
    ],
}

LEET_TRANSLATION = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
LEET_HINTS = re.compile(
    r"(?i)(?:\b[a-z]*\d[a-z]*\b|f(?:3|e){1,2}|urg(?:3|e)nt|p[a@]is[a@]|s[e3]cur[i1]ty|fr[e3]{2}|pr[i1]z[e3])")


def normalize_leetspeak(text: str) -> str:
    return text.translate(LEET_TRANSLATION)


def detect_leetspeak(text: str) -> dict[str, Any]:
    matches = LEET_HINTS.findall(text)
    detected = bool(matches) or bool(re.search(r"\b[a-zA-Z]+[013457@$][a-zA-Z]+\b", text))
    return {
        "detected": detected,
        "matched_tokens": sorted(set(matches), key=str.lower),
        "normalized_text": normalize_leetspeak(text),
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
    return {"matched": bool(matched_categories), "categories": matched_categories}


def mock_registration_intelligence(phone_number: str) -> dict[str, Any]:
    digits = re.sub(r"\D", "", phone_number)
    seed = int(digits[-4:]) if digits else 0
    registrations_30d = 2 + (seed % 19)
    registrations_24h = seed % 8
    return {
        "registration_velocity_high": (registrations_30d >= 15 or registrations_24h >= 5),
        "registrations_last_30_days": registrations_30d,
    }


def analyze_cross_domain_graph(phone: str, domain: Optional[str], ip: Optional[str]) -> dict[str, Any]:
    linked_cases = []
    shared_infrastructure = []
    for case in st.session_state["FRAUD_GRAPH_DB"]:
        has_link = False
        if case["phone"] == phone:
            has_link = True;
            shared_infrastructure.append("phone_number")
        if domain and domain != "unknown" and case["domain"] == domain:
            has_link = True;
            shared_infrastructure.append("shared_url_domain")
        if ip and ip != "192.168.1.1" and case["ip"] == ip:
            has_link = True;
            shared_infrastructure.append("infrastructure_ip")
        if has_link:
            linked_cases.append(case["id"])
    return {
        "fraud_ring_detected": len(linked_cases) > 0,
        "linked_historical_case_ids": linked_cases,
        "shared_infrastructure_edges": sorted(list(set(shared_infrastructure))),
        "graph_node_count": len(st.session_state["FRAUD_GRAPH_DB"]) + 1,
    }


def process_internal_risk(phone, text, carrier, ip, domain, logo_mismatch) -> dict[str, Any]:
    reg_data = mock_registration_intelligence(phone)
    leet_data = detect_leetspeak(text)
    scam_data = scan_scam_patterns(text)
    graph_data = analyze_cross_domain_graph(phone, domain, ip)

    current_hour = datetime.now(timezone.utc).hour
    suspicious_time = 2 = 75 else "HIGH" if final_score >= 50 else "MEDIUM" if final_score >= 25 else "LOW",
    "flags": flags,
    "cross_domain_graph": graph_data,
    "explainability": {"contributions": contributions},
    "heuristic_analysis": {"leetspeak": leet_data, "scam_pattern_scan": scam_data},
    "anomaly_detection": {"engine": "IsolationForest_Simulation_Layer",
                          "anomaly_score": 0.91 if (carrier == "VOIP" and logo_mismatch) else 0.18,
                          "outlier_status": (carrier == "VOIP" and logo_mismatch)}

}

# =====================================================================
#                      STREAMLIT WEB INTERFACE (UI)
# =====================================================================

st.title("🛡️ Multi-Domain Fraud & Risk Assessment")
st.caption("Advanced FYP PoC — Real-time Graph Infrastructure Layer & Unsupervised Outlier Analytics")
st.info(
    "Infrastructure data is verified dynamically across our graph module. No external static PTA production instances are affected during evaluation cycles.")

with st.sidebar:
    st.header("⚡ Assessment Input Parameters")
phone_number = st.text_input("Phone Number", value="+923001234567", placeholder="+923001234567")
message_text = st.text_area("Ad / Message Text",
                            value="Urg3nt! Ap ko in'am mila hai. Security fee 5000 paisa jama karain.", height=130)
carrier_type = st.selectbox("Carrier / Line Type", ["Mobile", "VOIP", "Fixed Line"], index=1)

st.subheader("🌐 Network Telemetry (Section 8)")
ip_address = st.text_input("Infrastructure IP Vector", value="192.168.43.10")
extracted_domain = st.text_input("Extracted Link URL Domain", value="bisp-reward-funds.com")

st.subheader("📸 Computer Vision Emulation")
logo_mismatch = st.checkbox("Flag Corporate Logo Mismatch (Stolen Identity)", value=False)

assess = st.button("🔍 Run Advanced Risk Analysis", type="primary", use_container_width=True)

if assess:
    st.session_state["advanced_assessment"] = process_internal_risk(phone_number, text=message_text,
                                                                    carrier=carrier_type, ip=ip_address,
                                                                    domain=extracted_domain,
                                                                    logo_mismatch=logo_mismatch)

result = st.session_state.get("advanced_assessment")

if not result:
    st.subheader("SSUET Unified Scoring Architecture Matrix")
st.markdown(
"""
- **VOIP Base Line Deployment Routing:** +20 Points
- **Leetspeak/Obfuscation Character Matches:** +15 Points
- **Roman Urdu Text Patterns & Key Match:** +25 Points
- **High Network Registration Telemetry Velocity:** +15 Points
- **Cross-Domain Fraud-Ring Connected Links:** +15 Points
- **Behavioral Outlier Time Anomalies:** +10 Points
- **Maximum Unified Bound Constraints:** 100 Max Cumulative Points
"""
)
st.stop()

score = result["risk_score"]
level = result["risk_level"]

left, right = st.columns([1, 1.7])

with left:
    st.subheader("Unified Structural Risk Score")
gauge = go.Figure(go.Indicator(
    mode="gauge+number", value=score, number={"suffix": "/100"}, title={"text": f"Status Evaluated: {level}"},
    gauge={
        "axis": {"range": [0, 100]}, "bar": {"thickness": 0.35, "color": "red" if score >= 50 else "orange"},
        "steps": [{"range":, "color": "lightgreen"}, {"range":, "color": "yellow"}, {"range":, "color": "orange"}, {
    "range":, "color": "coral"}],
}
))
gauge.update_layout(height=280, margin=dict(l=20, r=20, t=60, b=20))
st.plotly_chart(gauge, use_container_width=True)
st.metric("Unified Assessment Level", level)
st.progress(score / 100)
with right:
st.subheader("🚩 Active High-Risk Infrastructure Flags")
if result["flags"]:
for flag in result["flags"]: st.error(flag)
else: st.success("Clean Signature: Structural parameters fall inside trusted limits.")
st.divider()
col1, col2 = st.columns(2)
with col1:
st.subheader("🕸️ Cross-Domain Graph Network Links")
graph_data = result["cross_domain_graph"]
if graph_data["fraud_ring_detected"]:
st.warning(f"⚠️ Organized Fraud Ring Tracked! Shared vertices link with {len(graph_data['linked_historical_case_ids'])} prior records.")
st.write("Overlapping Threat Vectors:", ", ".join(graph_data["shared_infrastructure_edges"]))
else: st.success("✅ Isolation Check Passed: Node metrics do not correlate with existing adversarial infrastructure.")
st.metric("Active Fraud Graph Database Tracking Nodes", graph_data["graph_node_count"])
with col2:
st.subheader("🤖 Unsupervised Outlier Profiling")
anomaly = result["anomaly_detection"]
st.write(f"Statistical Processing Pipeline Engine: {anomaly['engine']}")
st.progress(anomaly["anomaly_score"])
st.caption(f"Density Outlier Index: {anomaly['anomaly_score']} (Structural Threshold: 0.70)")
if anomaly["outlier_status"]: st.error("🚨 Anomalous Behavior Profile Flagged: Multi-signature misalignment detected.")
else: st.info("ℹ️ Transaction signature profile is compliant with standard distribution limits.")
st.divider()
col3, col4 = st.columns(2)
with col3:
st.subheader("📊 Explainability Attribute Attribution")
for item in result["explainability"]["contributions"]:
factor = item["factor"].replace("_", " ").title()
st.write(f"{factor} — +{item['contribution_points']} Engine Points Allocation")
st.progress(item["contribution_points"] / 100)
st.caption(f"Accounts for {item['contribution_percent_of_final_score']}% of final structural assessment profile vector weight.")
with col4:
st.subheader("🔍 Localized Heuristic Parsing Findings")
scam_scan = result["heuristic_analysis"]["scam_pattern_scan"]
leet_scan = result["heuristic_analysis"]["leetspeak"]
st.write("Obfuscation Mask Matching:", "True Signature Found" if leet_scan["detected"] else "Clean Signatures Only")
if leet_scan["matched_tokens"]: st.write("Identified Tokens:", ", ".join(leet_scan["matched_tokens"]))
st.write("Roman Urdu Script Token Intersection:", "Scam Intercepted" if scam_scan["matched"] else "Normal Conversion Profile")
if scam_scan["categories"]: st.json(scam_scan["categories"])
st.divider()
with st.expander("🛠️ Advanced API Metadata Response JSON (For Evaluators)"):
st.json(result)
