# 🛡️ PhishGuard — Explainable Email Phishing Analyzer

An explainable, heuristic-and-AI-powered email security forensic tool that analyzes `.eml` files (headers, authentication, body content, and links) and outputs transparent classifications with evidence breakdowns. Every flag answers **"why"** rather than acting as a black-box score.

---

## 🚀 Features

- **Header Forensics**: Extracts and evaluates `From`, `Reply-To`, `Subject`, `Date`, and `Authentication-Results` headers.
- **Protocol Verification**:
  - **SPF** (Sender Policy Framework) pass/fail/none detection.
  - **DKIM** (DomainKeys Identified Mail) cryptographic signature validation.
  - **DMARC** policy alignment detection.
- **Identity & Spoofing Detection**:
  - **Reply-To Mismatch**: Identifies discrepancy between sender and reply routing.
  - **Display Name Impersonation**: Detects high-privilege brand words (e.g. IT Support, PayPal, Microsoft) paired with mismatched domains.
  - **Lookalike & Typosquat Domains**: Identifies fuzzy domain similarity against trusted brands using `difflib`.
- **Link & Network Threat Intelligence**:
  - **URL Shortener Detection**: Flags masked shorteners (`bit.ly`, `tinyurl.com`, `t.co`, etc.).
  - **Direct IP URLs**: Detects raw numeric IP destinations (`http://192.168.1.100/...`).
  - **Href vs Display Text Mismatch**: Detects deceptive hyperlinks where anchor text contradicts actual destination.
  - **Local Threat Blocklist & Allowlist**: Cross-checks domains against local CSV threat lists.
- **Content & Behavioral Analysis**:
  - **Urgency & Psychological Pressure**: Detects coercion keywords (e.g. "immediate action", "within 24 hours", "account suspended").
  - **Generic Greetings**: Identifies impersonal salutations common in bulk campaigns.
- **Explainability**:
  - Gemini 2.5 Flash plain-English AI explanations and security guidance.
  - Zero-dependency rule-based fallback when offline or no API key is provided.
- **Interactive SOC Dashboard**: Aggregate batch metrics, threat distributions, and forensic report downloads.

---

## 📁 Project Structure

```
phishing-analyzer/
├── app.py                     # Streamlit web application & SOC dashboard
├── requirements.txt           # Minimal dependencies
├── .env                       # Environment variables (GEMINI_API_KEY)
├── README.md                  # Project documentation
├── engine/
│   ├── __init__.py
│   ├── parser.py              # RFC 822 / MIME .eml parser & URL extractor
│   ├── rules.py               # 11+ heuristic detection checks
│   ├── reputation.py          # Allowlist, blocklist & lookalike domain matcher
│   ├── scorer.py              # Aggregated scoring & classification engine
│   └── explainer.py           # Gemini 2.5 Flash + fallback explainability engine
├── data/
│   ├── allowlist.csv          # Trusted organization domains
│   ├── blocklist.csv          # Known malicious domains and threat reasons
│   └── sample_emails/         # 6 benchmark test cases
│       ├── legit_college_notice.eml
│       ├── legit_newsletter.eml
│       ├── phish_domain_spoof.eml
│       ├── phish_urgent_creds.eml
│       ├── phish_spf_fail.eml
│       └── phish_url_shortener.eml
└── tests/
    └── test_rules.py          # Automated test suite
```

---

## ⚡ Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. (Optional) Configure Gemini API Key
In `.env` or in the application sidebar:
```env
GEMINI_API_KEY=your_gemini_api_key_here
```
*(If omitted, the built-in deterministic explainability engine generates full explanations automatically).*

### 3. Run Automated Tests
```bash
python -m unittest tests/test_rules.py
```

### 4. Launch the Web Application (SOC Dashboard)
```bash
streamlit run app.py
```

### 5. Launch the Chrome Extension Backend API
```bash
python api_server.py
```
*(Runs FastAPI server on `http://127.0.0.1:8000` for live Gmail analysis)*

### 6. Load Chrome Extension into Browser
1. Open Chrome and navigate to `chrome://extensions`
2. Enable **Developer mode** (toggle in top-right)
3. Click **Load unpacked**
4. Select the `extension/` folder inside this repository: `D:\Email_Analyzer\extension`
5. Open Gmail (`mail.google.com`) and open any email to see the **🛡️ Scan for Phishing** button!

---

## 🎯 Scoring Model & Thresholds

| Check | Weight | Trigger Condition |
| :--- | :---: | :--- |
| **SPF Fail** | `+20` | `spf=fail` in Authentication-Results |
| **DKIM Fail** | `+20` | `dkim=fail` in Authentication-Results |
| **DMARC Fail** | `+15` | `dmarc=fail` in Authentication-Results |
| **From vs Reply-To Mismatch** | `+15` | Reply-To domain differs from From domain |
| **Display Name Impersonation** | `+10` | Authority keyword in display name without matching domain |
| **Lookalike / Typosquat Domain** | `+20` | Domain similarity ratio $\ge 0.75$ to allowlisted brand |
| **URL Shortener Present** | `+10` | Masked shortener domain found in body links |
| **IP-Based URL** | `+15` | Direct numeric IP used in URL link |
| **Href / Display Text Mismatch** | `+15` | Anchor display domain $\neq$ href destination |
| **Urgency Keywords** | `+5 each` | Coercive urgency phrases (max 3 counted $\rightarrow +15$) |
| **Generic Greeting** | `+5` | Impersonal salutation ("Dear Customer/User") |
| **Domain Blocklist Match** | `+25` | Exact match in local threat intelligence blocklist |
| **Domain Allowlist Match** | `-20` | Exact match in verified safe domain list |

### Classification Tiers:
- **Score $\ge 50$**: 🚨 **Phishing** (High Risk)
- **Score $20 - 49$**: ⚠️ **Suspicious** (Moderate Risk)
- **Score $< 20$**: ✅ **Safe** (Low Risk)
