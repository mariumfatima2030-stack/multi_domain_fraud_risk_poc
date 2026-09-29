from __future__ import annotations

import requests
import streamlit as st
import plotly.graph_objects as go

BACKEND_BASE_URL = "http://127.0.0.1:8000"
BACKEND_URL = f"{BACKEND_BASE_URL}/api/v1/assess-risk"

st.set_page_config(
    page_title="Fraud & Risk Assessment",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Multi-Domain Fraud & Risk Assessment")
st.caption("Local PoC — FastAPI + Streamlit + Regex/Scikit-learn-ready architecture")

st.info(
    "Infrastructure data is mocked locally. No real telecom/PTA system, subscriber "
    "database, or external API is accessed."
)

with st.sidebar:
    st.header("Assessment Input")

    phone_number = st.text_input(
        "Phone Number",
        value="+923001234567",
        placeholder="+923001234567",
    )

    message_text = st.text_area(
        "Ad / Message Text",
        value="Urg3nt! Ap ko in'am mila hai. Security fee 5000 paisa jama karain.",
        height=150,
        help="Supports Roman Urdu, scam keywords, and leetspeak such as f33 or urg3nt.",
    )

    carrier_type = st.selectbox(
        "Carrier / Line Type",
        ["Mobile", "VOIP", "Fixed Line"],
        index=1,
    )

    assess = st.button(
        "🔍 Assess Risk",
        type="primary",
        use_container_width=True,
    )

if assess:
    payload = {
        "phone_number": phone_number,
        "message_text": message_text,
        "carrier_type": carrier_type,
    }

    try:
        with st.spinner("Running local fraud/risk assessment..."):
            response = requests.post(
                BACKEND_URL,
                json=payload,
                timeout=10,
            )

        if response.ok:
            st.session_state["assessment"] = response.json()
        else:
            try:
                detail = response.json().get("detail", response.text)
            except ValueError:
                detail = response.text

            st.error(
                f"Backend returned HTTP {response.status_code}: {detail}"
            )

    except requests.RequestException:
        st.error(
            "Could not connect to FastAPI. Start the backend first with: "
            "uvicorn app_backend:app --reload"
        )

result = st.session_state.get("assessment")

if not result:
    st.subheader("How the PoC scores risk")

    st.markdown(
        """
        - **VOIP line:** +25
        - **Leetspeak detected:** +20
        - **Roman Urdu/scam text matched:** +35
        - **Registration velocity too high:** +20
        - **Maximum unified score:** 100
        """
    )

    st.stop()

score = result["risk_score"]
level = result["risk_level"]

left, right = st.columns([1, 1.7])

with left:
    st.subheader("Unified Risk Score")

    gauge = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"suffix": "/100"},
            title={"text": level},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"thickness": 0.35},
                "steps": [
                    {"range": [0, 25]},
                    {"range": [25, 50]},
                    {"range": [50, 75]},
                    {"range": [75, 100]},
                ],
            },
        )
    )

    gauge.update_layout(
        height=300,
        margin=dict(l=20, r=20, t=60, b=20),
    )

    st.plotly_chart(gauge, use_container_width=True)

    st.metric("Risk Level", level)
    st.progress(score / 100)

with right:
    st.subheader("🚩 High-Risk Flags")

    flags = result["flags"]

    if flags:
        for flag in flags:
            st.error(flag)
    else:
        st.success("No configured high-risk flags were triggered.")

st.divider()

col1, col2 = st.columns(2)

with col1:
    st.subheader("Factor Contribution")

    contributions = result["explainability"]["contributions"]

    for item in contributions:
        factor = item["factor"].replace("_", " ").title()
        points = item["contribution_points"]
        percentage = item["contribution_percent_of_final_score"]

        st.write(f"**{factor}** — +{points} points")
        st.progress(points / 100)
        st.caption(f"{percentage}% of the final score")

with col2:
    st.subheader("Heuristic Findings")

    scam_scan = result["heuristic_analysis"]["scam_pattern_scan"]
    leet_scan = result["heuristic_analysis"]["leetspeak"]

    st.write(
        "**Leetspeak detected:**",
        "Yes" if leet_scan["detected"] else "No",
    )

    if leet_scan["matched_tokens"]:
        st.write(
            "Matched tokens:",
            ", ".join(leet_scan["matched_tokens"]),
        )

    st.write(
        "**Roman Urdu/scam text matched:**",
        "Yes" if scam_scan["matched"] else "No",
    )

    if scam_scan["categories"]:
        st.json(scam_scan["categories"])

st.divider()

st.subheader("Mock Infrastructure Intelligence")

infra_col1, infra_col2 = st.columns(2)

with infra_col1:
    st.markdown("**Carrier Lookup**")
    st.json(result["infrastructure"]["carrier_lookup"])

with infra_col2:
    st.markdown("**Registration Intelligence**")
    st.json(result["infrastructure"]["registration_intelligence"])

with st.expander("SHAP-Style Explainability JSON"):
    st.json(result["explainability"])

with st.expander("Complete API Response JSON"):
    st.json(result)
