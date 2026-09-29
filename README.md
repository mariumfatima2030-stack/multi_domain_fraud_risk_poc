# Multi-Domain Fraud and Risk Assessment API — Local PoC

A fully local Final Year Project proof-of-concept for assessing fraud/risk signals from:

- Phone number
- Ad/message text
- Carrier/line type
- Mock telecom/registration intelligence

## Architecture

```text
Streamlit Dashboard
        |
        | POST /api/v1/assess-risk
        v
FastAPI Backend
        |
        +--> Mock Carrier Lookup
        +--> Mock Registration Intelligence
        +--> Leetspeak Detector
        +--> Roman Urdu / Scam Keyword Engine
        +--> Weighted Risk Engine
        +--> SHAP-style Explanation
```

No real PTA, telecom carrier, subscriber database, or external API is used.

## Requirements

Python 3.10+ is recommended.

## 1. Create and activate a virtual environment

### Windows PowerShell

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use:

```powershell
.venv\Scripts\activate.bat
```

### macOS/Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 2. Install dependencies

```bash
python -m pip install --upgrade pip
pip install fastapi uvicorn[standard] streamlit requests plotly scikit-learn
```

Scikit-learn is included because it is part of the planned ML layer. The current PoC intentionally uses lightweight deterministic heuristics instead of downloading a transformer model.

## 3. Start the FastAPI backend

Open Terminal 1:

```bash
uvicorn app_backend:app --reload
```

Backend:

```text
http://127.0.0.1:8000
```

Swagger API documentation:

```text
http://127.0.0.1:8000/docs
```

Health check:

```text
http://127.0.0.1:8000/health
```

## 4. Start the Streamlit frontend

Open Terminal 2 in the same project folder and activate the same virtual environment.

```bash
streamlit run app_frontend.py
```

The dashboard will normally open at:

```text
http://localhost:8501
```

## Risk Formula

The PoC uses the exact requested weighted factors:

| Factor | Points |
|---|---:|
| VOIP line | +25 |
| Leetspeak detected | +20 |
| Roman Urdu/scam text matched | +35 |
| Registration velocity too high | +20 |
| Maximum | 100 |

The final score is:

```text
Risk Score = min(100, sum(triggered factor weights))
```

## Mock Registration Pipeline

The backend generates deterministic but realistic-looking registration intelligence from the phone number digits. This makes the demo repeatable without pretending to have real PTA data.

Example mocked fields:

```json
{
  "source": "MOCK_PTA_REGISTRATION_SERVICE",
  "subscriber_status": "active",
  "sim_age_days": 412,
  "registrations_last_30_days": 18,
  "registrations_last_24_hours": 6,
  "velocity_threshold_30d": 15,
  "velocity_threshold_24h": 5,
  "registration_velocity_high": true
}
```

## Example API Request

```json
{
  "phone_number": "+923001234567",
  "message_text": "Urg3nt! Ap ko in'am mila hai. Security fee 5000 paisa jama karain.",
  "carrier_type": "VOIP"
}
```

## Example API Response Shape

```json
{
  "risk_score": 100,
  "risk_level": "CRITICAL",
  "flags": [
    "VOIP line type",
    "Leetspeak/obfuscation detected",
    "Roman Urdu/scam keywords detected: security_fee, paisa, inam",
    "High registration velocity"
  ],
  "explainability": {
    "method": "SHAP_STYLE_WEIGHTED_BREAKDOWN",
    "base_score": 0,
    "final_score": 100,
    "total_possible_points": 100,
    "contributions": []
  }
}
```

## Future ML Integration

Two explicit placeholders are included in `app_backend.py`:

1. `transformer_nlp_placeholder()`
   - Intended future model: XLM-RoBERTa or another multilingual transformer.
   - Purpose: semantic scam classification and multilingual/Roman Urdu understanding.

2. `shap_explainability_placeholder()`
   - Intended future library: SHAP.
   - Purpose: replace the deterministic weighted explanation with actual model-level SHAP values.

The current PoC does not download large ML models, so it is suitable for a laptop-based FYP demonstration.

## Test the API from PowerShell

With the backend running:

```powershell
$body = @{
    phone_number = "+923001234567"
    message_text = "Urg3nt! Ap ko in'am mila hai. Security fee 5000 paisa jama karain."
    carrier_type = "VOIP"
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "http://127.0.0.1:8000/api/v1/assess-risk" `
    -Method Post `
    -ContentType "application/json" `
    -Body $body
```

## Project Structure

```text
multi_domain_fraud_risk_poc/
│
├── app_backend.py
├── app_frontend.py
└── README.md
```
