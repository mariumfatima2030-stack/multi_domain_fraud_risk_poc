from __future__ import annotations

import requests
import streamlit as st
import plotly.graph_objects as go


# =====================================================================
#                         PAGE CONFIGURATION
# =====================================================================

st.set_page_config(
    page_title="SSUET Advanced Fraud Dashboard",
    page_icon="🛡️",
    layout="wide",
)


# =====================================================================
#                         BACKEND CONFIGURATION
# =====================================================================

BACKEND_BASE_URL = "http://127.0.0.1:8000"
BACKEND_URL = f"{BACKEND_BASE_URL}/api/v1/assess-risk"


# =====================================================================
#                         SESSION STATE
# =====================================================================

if "advanced_assessment" not in st.session_state:
    st.session_state["advanced_assessment"] = None


# =====================================================================
#                         PAGE HEADER
# =====================================================================

st.title("🛡️ Multi-Domain Fraud & Risk Assessment")

st.caption(
    "Advanced FYP PoC — Real-time Graph Infrastructure Layer "
    "& Unsupervised Outlier Analytics"
)

st.info(
    "Infrastructure data is evaluated through the fraud-risk "
    "assessment engine. Registration intelligence shown in this "
    "PoC is simulated/mock data for academic evaluation."
)


# =====================================================================
#                         SIDEBAR INPUT
# =====================================================================

with st.sidebar:

    st.header("⚡ Assessment Input Parameters")

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
            "Supports Roman Urdu scam-pattern analysis "
            "and leetspeak detection."
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

    st.subheader("🌐 Network Telemetry")

    ip_address = st.text_input(
        "Infrastructure IP Vector",
        value="192.168.43.10",
        help=(
            "Used by the graph simulation to identify "
            "shared infrastructure."
        ),
    )

    extracted_domain = st.text_input(
        "Extracted Link URL Domain",
        value="bisp-reward-funds.com",
        help=(
            "Used by the graph simulation to identify "
            "shared suspicious domains."
        ),
    )

    st.subheader("📸 Computer Vision Emulation")

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


# =====================================================================
#                         CLEAR RESULT
# =====================================================================

if clear:
    st.session_state["advanced_assessment"] = None
    st.rerun()


# =====================================================================
#                         API REQUEST
# =====================================================================

if assess:

    payload = {
        "phone_number": phone_number,
        "message_text": message_text,
        "carrier_type": carrier_type,
        "ip_address": ip_address,
        "extracted_domain": extracted_domain,
        "logo_mismatch_detected": logo_mismatch,
    }

    try:

        with st.spinner("🔄 Running advanced fraud-risk analysis..."):

            response = requests.post(
                BACKEND_URL,
                json=payload,
                timeout=30,
            )

        if response.status_code == 200:

            st.session_state["advanced_assessment"] = (
                response.json()
            )

            st.success(
                "✅ Risk assessment completed successfully."
            )

        else:

            try:
                error_data = response.json()
            except Exception:
                error_data = response.text

            st.error(
                f"Backend returned HTTP {response.status_code}"
            )

            st.code(str(error_data))

    except requests.exceptions.ConnectionError:

        st.error(
            "❌ Cannot connect to FastAPI backend.\n\n"
            "Make sure the backend is running on "
            f"{BACKEND_BASE_URL}"
        )

    except requests.exceptions.Timeout:

        st.error(
            "⏱️ Backend request timed out. "
            "Please check whether FastAPI is running correctly."
        )

    except requests.exceptions.RequestException as exc:

        st.error(
            f"❌ Backend request failed: {exc}"
        )

    except Exception as exc:

        st.error(
            f"❌ Unexpected error: {exc}"
        )


# =====================================================================
#                         GET RESULT
# =====================================================================

result = st.session_state.get(
    "advanced_assessment"
)


# =====================================================================
#                         INITIAL SCREEN
# =====================================================================

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
        "Enter assessment parameters from the sidebar and click "
        "**Run Advanced Risk Analysis**."
    )

    st.stop()


# =====================================================================
#                         RESULT DATA
# =====================================================================

score = int(
    result.get("risk_score", 0)
)

level = result.get(
    "risk_level",
    "UNKNOWN"
)

flags = result.get(
    "flags",
    []
)

graph_data = result.get(
    "cross_domain_graph",
    {}
)

anomaly = result.get(
    "anomaly_detection",
    {}
)

explainability = result.get(
    "explainability",
    {}
)

heuristic = result.get(
    "heuristic_analysis",
    {}
)

scam_scan = heuristic.get(
    "scam_pattern_scan",
    {}
)

leet_scan = heuristic.get(
    "leetspeak",
    {}
)


# =====================================================================
#                         SCORE HEADER
# =====================================================================

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
            0
        ),
    )


st.divider()


# =====================================================================
#                         MAIN DASHBOARD
# =====================================================================

left, right = st.columns(
    [1, 1.7]
)


# =====================================================================
#                         RISK GAUGE
# =====================================================================

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
                    "size": 42
                },
            },

            title={
                "text": (
                    f"Status Evaluated: "
                    f"<b>{level}</b>"
                )
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
        min(max(score / 100, 0.0), 1.0)
    )


# =====================================================================
#                         FLAGS
# =====================================================================

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


# =====================================================================
#                         GRAPH + ANOMALY
# =====================================================================

st.divider()

col1, col2 = st.columns(2)


# =====================================================================
#                         GRAPH NETWORK
# =====================================================================

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


# =====================================================================
#                         ANOMALY PROFILING
# =====================================================================

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


# =====================================================================
#                         EXPLAINABILITY
# =====================================================================

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


# =====================================================================
#                         HEURISTIC ANALYSIS
# =====================================================================

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


# =====================================================================
#                         REQUEST INFORMATION
# =====================================================================

st.divider()

st.subheader(
    "📡 Assessment Request Information"
)

request_data = result.get(
    "request",
    {}
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


# =====================================================================
#                         ADVANCED JSON
# =====================================================================

st.divider()

with st.expander(
    "🛠️ Advanced API Metadata Response JSON (For Evaluators)"
):

    st.json(result)


# =====================================================================
#                         FOOTER
# =====================================================================

st.divider()

st.caption(
    "SSUET Computer Engineering — Final Year Project "
    "Advanced Proof of Concept"
)
