import os
import json
import pandas as pd
import streamlit as st
from engine import parser, scorer, explainer, reputation, rules

# Page configuration
st.set_page_config(
    page_title="PhishGuard — Explainable Email Phishing Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for rich dark cyber-defense aesthetics
st.markdown("""
<style>
    /* Global Font & Background Styling */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }

    /* Main App Header */
    .phishguard-hero {
        display: flex;
        align-items: center;
        gap: 18px;
        padding: 20px 24px;
        background: linear-gradient(135deg, rgba(79, 70, 229, 0.15) 0%, rgba(15, 23, 42, 0.6) 100%);
        border: 1px solid rgba(99, 102, 241, 0.3);
        border-radius: 16px;
        margin-bottom: 24px;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.35);
    }
    .phishguard-hero-icon {
        font-size: 42px;
        line-height: 1;
        filter: drop-shadow(0 0 12px rgba(99, 102, 241, 0.5));
    }
    .main-header {
        font-size: 2.1rem;
        font-weight: 800;
        background: linear-gradient(135deg, #FFFFFF 0%, #E2E8F0 50%, #A5B4FC 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
        letter-spacing: -0.5px;
    }
    .sub-header {
        font-size: 0.95rem;
        color: #94A3B8;
        margin-top: 4px;
        margin-bottom: 0;
    }

    /* Primary Action Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #4F46E5 0%, #7C3AED 100%) !important;
        color: #FFFFFF !important;
        font-weight: 600 !important;
        border: 1px solid rgba(255, 255, 255, 0.15) !important;
        border-radius: 10px !important;
        padding: 10px 20px !important;
        box-shadow: 0 4px 14px rgba(79, 70, 229, 0.35) !important;
        transition: all 0.2s ease !important;
    }
    .stButton > button:hover {
        background: linear-gradient(135deg, #4338CA 0%, #6D28D9 100%) !important;
        box-shadow: 0 6px 20px rgba(124, 58, 237, 0.5) !important;
        transform: translateY(-1px) !important;
    }

    /* Download Buttons */
    .stDownloadButton > button {
        background: #1E293B !important;
        color: #E2E8F0 !important;
        border: 1px solid #334155 !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        transition: all 0.2s ease !important;
    }
    .stDownloadButton > button:hover {
        background: #334155 !important;
        color: #FFFFFF !important;
        border-color: #64748B !important;
    }

    /* File Uploader Container */
    [data-testid="stFileUploader"] {
        background: #111C33;
        border: 2px dashed rgba(99, 102, 241, 0.4);
        border-radius: 14px;
        padding: 16px 20px;
        transition: all 0.2s ease;
    }
    [data-testid="stFileUploader"]:hover {
        border-color: #818CF8;
        background: #14213D;
    }

    /* Prominent Result Banner Card */
    .result-banner {
        background: #1E293B;
        border-radius: 14px;
        padding: 18px 22px;
        margin-bottom: 1.5rem;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.35);
        display: flex;
        justify-content: space-between;
        align-items: center;
        border: 1px solid rgba(255, 255, 255, 0.08);
    }
    .result-banner-phishing {
        border-left: 6px solid #EF4444;
        box-shadow: 0 10px 30px rgba(239, 68, 68, 0.15), 0 0 0 1px rgba(239, 68, 68, 0.3);
    }
    .result-banner-suspicious {
        border-left: 6px solid #F59E0B;
        box-shadow: 0 10px 30px rgba(245, 158, 11, 0.15), 0 0 0 1px rgba(245, 158, 11, 0.3);
    }
    .result-banner-safe {
        border-left: 6px solid #10B981;
        box-shadow: 0 10px 30px rgba(16, 185, 129, 0.12), 0 0 0 1px rgba(16, 185, 129, 0.3);
    }

    .result-banner-left {
        flex: 1;
        overflow: hidden;
    }
    .result-header-row {
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .result-icon {
        font-size: 22px;
    }
    .result-filename {
        margin: 0;
        color: #F8FAFC;
        font-size: 1.25rem;
        font-weight: 700;
        letter-spacing: -0.2px;
    }
    .result-meta-row {
        color: #94A3B8;
        font-size: 0.88rem;
        margin-top: 6px;
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        align-items: center;
    }
    .result-meta-row code {
        background: #0F172A;
        padding: 2px 6px;
        border-radius: 4px;
        color: #CBD5E1;
        font-size: 0.82rem;
    }
    .meta-separator {
        color: #475569;
    }

    .result-banner-right {
        display: flex;
        align-items: center;
        gap: 14px;
        margin-left: 16px;
    }
    .result-badge {
        display: inline-block;
        padding: 6px 14px;
        border-radius: 20px;
        font-size: 0.85rem;
        font-weight: 800;
        letter-spacing: 0.5px;
        text-transform: uppercase;
    }
    .badge-safe {
        background: rgba(16, 185, 129, 0.18);
        color: #34D399;
        border: 1px solid rgba(16, 185, 129, 0.45);
        text-shadow: 0 0 10px rgba(16, 185, 129, 0.3);
    }
    .badge-suspicious {
        background: rgba(245, 158, 11, 0.18);
        color: #FBBF24;
        border: 1px solid rgba(245, 158, 11, 0.45);
        text-shadow: 0 0 10px rgba(245, 158, 11, 0.3);
    }
    .badge-phish {
        background: rgba(239, 68, 68, 0.18);
        color: #F87171;
        border: 1px solid rgba(239, 68, 68, 0.45);
        text-shadow: 0 0 10px rgba(239, 68, 68, 0.3);
    }

    .result-score-chip {
        display: flex;
        flex-direction: column;
        align-items: center;
        background: #0F172A;
        padding: 6px 12px;
        border-radius: 10px;
        border: 1px solid #334155;
    }
    .score-label {
        font-size: 0.65rem;
        font-weight: 700;
        text-transform: uppercase;
        color: #64748B;
        letter-spacing: 0.5px;
    }
    .score-val {
        font-size: 1.15rem;
        font-weight: 800;
        color: #F8FAFC;
        line-height: 1;
    }
    .score-denom {
        font-size: 0.7rem;
        color: #94A3B8;
        font-weight: 600;
    }

    /* Evidence Items with Category Accent */
    .evidence-item {
        background: #111C33;
        border-left: 4px solid #EF4444;
        padding: 10px 14px;
        margin: 8px 0;
        border-radius: 0 10px 10px 0;
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-left-width: 4px;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.2);
    }
    .evidence-pass {
        background: #111C33;
        border-left: 4px solid #10B981;
        padding: 9px 14px;
        margin: 6px 0;
        border-radius: 0 10px 10px 0;
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-left-width: 4px;
    }
    .evidence-top {
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .evidence-name {
        font-size: 0.92rem;
        font-weight: 700;
        color: #F1F5F9;
        display: flex;
        align-items: center;
        gap: 6px;
    }
    .evidence-pts-badge {
        font-size: 0.75rem;
        font-weight: 800;
        background: rgba(239, 68, 68, 0.2);
        border: 1px solid rgba(239, 68, 68, 0.45);
        color: #FCA5A5;
        padding: 2px 8px;
        border-radius: 6px;
    }
    .evidence-desc {
        color: #CBD5E1;
        font-size: 0.85rem;
        margin-top: 4px;
        line-height: 1.4;
    }

    /* Dashboard KPI Card Styling */
    .kpi-card {
        background: #1E293B;
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 16px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
        text-align: center;
    }
    .kpi-title {
        font-size: 0.78rem;
        font-weight: 700;
        text-transform: uppercase;
        color: #94A3B8;
        letter-spacing: 0.5px;
    }
    .kpi-value {
        font-size: 1.7rem;
        font-weight: 800;
        color: #F8FAFC;
        margin-top: 4px;
    }
</style>
""", unsafe_allow_html=True)

def get_check_icon(check_name: str) -> str:
    """Returns a relevant security icon for scannable evidence categorization."""
    c = str(check_name).lower()
    if any(k in c for k in ["spf", "dkim", "dmarc", "auth"]):
        return "🔒"
    elif any(k in c for k in ["from", "reply-to", "display", "impersonation", "brand", "lookalike", "typosquat"]):
        return "👤"
    elif any(k in c for k in ["url", "shortener", "ip-address", "href", "link", "blocklist", "allowlist"]):
        return "🔗"
    elif any(k in c for k in ["urgency", "pressure", "credential", "threat", "greeting", "salutation"]):
        return "⚠️"
    return "🛡️"

SAMPLE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "sample_emails")

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.markdown("### 🛡️ PhishGuard Engine")
    st.caption("Explainable Email Heuristics & AI Forensics")

    st.markdown("---")
    st.markdown("#### ⚙️ AI Engine Settings")
    api_key_input = st.text_input(
        "Gemini API Key (Optional)",
        value=os.getenv("GEMINI_API_KEY", ""),
        type="password",
        help="Optional: Adds Gemini 2.5 Flash explanations. If blank, built-in heuristic explanations are used."
    )
    if api_key_input:
        os.environ["GEMINI_API_KEY"] = api_key_input
        st.success("✨ Gemini AI explainer enabled")
    else:
        st.info("ℹ️ Using built-in explainability engine")

    st.markdown("---")
    st.markdown("#### ⚡ Quick Demo Samples")
    if st.button("📥 Load 6 Benchmark Samples", use_container_width=True):
        sample_results = []
        sample_files = [
            "legit_college_notice.eml",
            "legit_newsletter.eml",
            "phish_domain_spoof.eml",
            "phish_urgent_creds.eml",
            "phish_spf_fail.eml",
            "phish_url_shortener.eml"
        ]
        for fname in sample_files:
            fpath = os.path.join(SAMPLE_DIR, fname)
            if os.path.exists(fpath):
                parsed = parser.parse_eml(fpath)
                result = scorer.score_email(parsed)
                explanation_data = explainer.explain(result["evidence"], result["classification"], parsed)
                result["explanation_data"] = explanation_data
                result["filename"] = fname
                result["parsed"] = parsed
                sample_results.append(result)
        st.session_state["analyzed_results"] = sample_results
        st.success("Loaded 6 test samples!")

    st.markdown("---")
    with st.expander("📖 Detection Rules & Weights"):
        st.markdown("""
        - **SPF Failure**: +20 pts
        - **DKIM Failure**: +20 pts
        - **DMARC Failure**: +15 pts
        - **Reply-To Mismatch**: +15 pts
        - **Display Impersonation**: +10 pts
        - **Lookalike Domain**: +20 pts
        - **URL Shortener**: +10 pts
        - **IP-Address URL**: +15 pts
        - **Href Mismatch**: +15 pts
        - **Urgency Phrases**: +5 pts each (max +15)
        - **Generic Greeting**: +5 pts
        - **Blocklist Match**: +25 pts
        - **Allowlist Match**: -20 pts
        """)

# Header
st.markdown("""
<div class="phishguard-hero">
    <div class="phishguard-hero-icon">🛡️</div>
    <div>
        <div class="main-header">PhishGuard Security Intelligence</div>
        <div class="sub-header">Explainable email forensics, cryptographic header verification & real-time phishing detection.</div>
    </div>
</div>
""", unsafe_allow_html=True)

# Tabs
tab_analyze, tab_dashboard = st.tabs(["🔍 Analyze & Forensics", "📊 SOC Metrics & Aggregate Dashboard"])

with tab_analyze:
    uploaded_files = st.file_uploader(
        "Upload one or more RFC 822 / MIME (.eml) files to inspect",
        type=["eml"],
        accept_multiple_files=True,
        help="Drag and drop raw .eml emails here"
    )

    # Process uploads
    if uploaded_files:
        current_results = []
        for uf in uploaded_files:
            try:
                content = uf.read()
                parsed = parser.parse_eml(content)
                result = scorer.score_email(parsed)
                explanation_data = explainer.explain(result["evidence"], result["classification"], parsed)
                result["explanation_data"] = explanation_data
                result["filename"] = uf.name
                result["parsed"] = parsed
                current_results.append(result)
            except Exception as ex:
                st.error(f"Error parsing {uf.name}: {str(ex)}")
        st.session_state["analyzed_results"] = current_results

    results = st.session_state.get("analyzed_results", [])

    if not results:
        st.info("👋 Upload an `.eml` file above or click **'Load 6 Benchmark Samples'** in the sidebar to start.")
    else:
        st.markdown(f"### 📋 Analysis Results ({len(results)} email{'s' if len(results) > 1 else ''} scanned)")

        for res in results:
            classification = res["classification"]
            score = res["score"]
            color = res["color"]
            fname = res["filename"]
            parsed = res["parsed"]
            explanation = res["explanation_data"]
            flagged = res["flagged"]
            passed = res["passed"]

            # Visual header banner
            banner_theme = "result-banner-safe"
            if classification == "Phishing":
                banner_theme = "result-banner-phishing"
                badge_class = "badge-phish"
                header_icon = "🚨"
            elif classification == "Suspicious":
                banner_theme = "result-banner-suspicious"
                badge_class = "badge-suspicious"
                header_icon = "⚠️"
            else:
                badge_class = "badge-safe"
                header_icon = "🛡️"

            with st.container():
                st.markdown(f"""
                <div class="result-banner {banner_theme}">
                    <div class="result-banner-left">
                        <div class="result-header-row">
                            <span class="result-icon">{header_icon}</span>
                            <h3 class="result-filename">{fname}</h3>
                        </div>
                        <div class="result-meta-row">
                            <span><strong>Subject:</strong> {parsed.get('subject') or '(No Subject)'}</span>
                            <span class="meta-separator">•</span>
                            <span><strong>From:</strong> <code>{parsed.get('from')}</code></span>
                        </div>
                    </div>
                    <div class="result-banner-right">
                        <span class="result-badge {badge_class}">{classification.upper()}</span>
                        <div class="result-score-chip">
                            <span class="score-label">Threat Score</span>
                            <span class="score-val">{score}</span>
                            <span class="score-denom">/100</span>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                col_left, col_right = st.columns([3, 2])

                with col_left:
                    # Plain English explanation card
                    st.markdown("#### 💡 Explainable AI Analysis & Guidance")
                    st.info(f"**Explanation:** {explanation['summary']}\n\n**🛡️ Recommended Action:** {explanation['recommendation']}\n\n*Source: {explanation.get('source', 'Engine')}*")

                    # Flagged evidence with category icons
                    st.markdown(f"#### ⚠️ Triggered Threat Indicators ({len(flagged)})")
                    if flagged:
                        for f in flagged:
                            cat_icon = get_check_icon(f['check'])
                            st.markdown(f"""
                            <div class="evidence-item">
                                <div class="evidence-top">
                                    <div class="evidence-name"><span>{cat_icon}</span> <strong>{f['check']}</strong></div>
                                    <span class="evidence-pts-badge">+{f['weight']} pts</span>
                                </div>
                                <div class="evidence-desc">{f['explanation']}</div>
                            </div>
                            """, unsafe_allow_html=True)
                    else:
                        st.success("No malicious threat indicators triggered.")

                with col_right:
                    # Key Header Details
                    st.markdown("#### 🔍 Header & Verification")
                    auth_raw = parsed.get("auth_results", "") or "No auth results header"
                    
                    st.markdown(f"""
                    - **From Domain:** `{parsed.get('from_domain') or 'N/A'}`
                    - **Reply-To:** `{parsed.get('reply_to') or '(Same as From)'}`
                    - **Date:** `{parsed.get('date') or 'N/A'}`
                    - **Authentication Header:**
                    ```text
                    {auth_raw[:150]}...
                    ```
                    """)

                    # Category breakdown chart
                    cat_df = pd.DataFrame(
                        list(res["category_scores"].items()),
                        columns=["Category", "Score"]
                    )
                    st.caption("Category Threat Weights")
                    st.bar_chart(cat_df.set_index("Category"))

                # URLs & Links Table
                if parsed.get("urls"):
                    with st.expander(f"🔗 Extracted URLs ({len(parsed['urls'])}) & Link Inspection"):
                        links_data = []
                        for u in parsed["urls"]:
                            d = reputation.extract_domain_from_url(u)
                            is_short = "⚠️ Yes" if d in rules.SHORTENER_DOMAINS else "No"
                            is_ip = "🚨 IP Host" if any(c.isdigit() for c in d.replace('.', '')) and d.replace('.', '').isdigit() else "Domain"
                            links_data.append({"URL": u, "Domain": d, "Shortened": is_short, "Type": is_ip})
                        st.dataframe(pd.DataFrame(links_data), use_container_width=True)

                # Passed Checks & Raw Data
                with st.expander("🔎 Passed Checks & Raw Email Inspection"):
                    tab_passed, tab_body = st.tabs(["Passed Checks", "Extracted Email Body"])
                    with tab_passed:
                        for p in passed:
                            cat_icon = get_check_icon(p['check'])
                            st.markdown(f"""
                            <div class="evidence-pass">
                                <div class="evidence-top">
                                    <div class="evidence-name"><span style="color:#10B981;">✔</span> <span>{cat_icon}</span> <strong>{p['check']}</strong></div>
                                    <span style="font-size:0.75rem; color:#10B981; font-weight:700;">PASS</span>
                                </div>
                                <div class="evidence-desc">{p['explanation']}</div>
                            </div>
                            """, unsafe_allow_html=True)
                    with tab_body:
                        st.text_area("Decoded Body Content", parsed.get("body", ""), height=180)

                # Report Download
                report_json = json.dumps({
                    "filename": fname,
                    "classification": classification,
                    "score": score,
                    "explanation": explanation,
                    "flagged_evidence": flagged,
                    "headers": {
                        "from": parsed.get("from"),
                        "reply_to": parsed.get("reply_to"),
                        "subject": parsed.get("subject"),
                        "date": parsed.get("date"),
                        "auth_results": parsed.get("auth_results")
                    },
                    "urls": parsed.get("urls")
                }, indent=2)

                st.download_button(
                    label=f"💾 Download Forensic Report ({fname}.json)",
                    data=report_json,
                    file_name=f"report_{fname}.json",
                    mime="application/json",
                    key=f"dl_{fname}"
                )
                st.markdown("---")

with tab_dashboard:
    results = st.session_state.get("analyzed_results", [])
    if not results:
        st.info("No emails analyzed yet. Upload files or load samples in the Analyze tab.")
    else:
        st.markdown("### 📊 Security Operations & Threat Analytics")

        df = pd.DataFrame([
            {
                "Filename": r["filename"],
                "Classification": r["classification"],
                "Threat Score": r["score"],
                "Sender Domain": r["from_domain"],
                "Flagged Count": len(r["flagged"]),
                "URL Count": r["url_count"],
            }
            for r in results
        ])

        # KPI Metrics
        total_scanned = len(results)
        phish_count = sum(1 for r in results if r["classification"] == "Phishing")
        suspicious_count = sum(1 for r in results if r["classification"] == "Suspicious")
        safe_count = sum(1 for r in results if r["classification"] == "Safe")
        avg_score = sum(r["score"] for r in results) / total_scanned

        m1, m2, m3, m4, m5 = st.columns(5)
        with m1:
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Total Scanned</div>
                <div class="kpi-value">{total_scanned}</div>
            </div>
            """, unsafe_allow_html=True)
        with m2:
            st.markdown(f"""
            <div class="kpi-card" style="border-left: 4px solid #EF4444;">
                <div class="kpi-title" style="color:#FCA5A5;">Phishing Detected</div>
                <div class="kpi-value" style="color:#EF4444;">{phish_count} <span style="font-size:0.85rem; color:#94A3B8;">({(phish_count/total_scanned)*100:.0f}%)</span></div>
            </div>
            """, unsafe_allow_html=True)
        with m3:
            st.markdown(f"""
            <div class="kpi-card" style="border-left: 4px solid #F59E0B;">
                <div class="kpi-title" style="color:#FCD34D;">Suspicious</div>
                <div class="kpi-value" style="color:#F59E0B;">{suspicious_count}</div>
            </div>
            """, unsafe_allow_html=True)
        with m4:
            st.markdown(f"""
            <div class="kpi-card" style="border-left: 4px solid #10B981;">
                <div class="kpi-title" style="color:#6EE7B7;">Safe / Legitimate</div>
                <div class="kpi-value" style="color:#10B981;">{safe_count}</div>
            </div>
            """, unsafe_allow_html=True)
        with m5:
            st.markdown(f"""
            <div class="kpi-card" style="border-left: 4px solid #6366F1;">
                <div class="kpi-title" style="color:#A5B4FC;">Avg Threat Score</div>
                <div class="kpi-value" style="color:#818CF8;">{avg_score:.1f}<span style="font-size:0.85rem; color:#94A3B8;">/100</span></div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='margin-top: 1.5rem;'></div>", unsafe_allow_html=True)

        col_d1, col_d2 = st.columns(2)

        with col_d1:
            st.markdown("#### 🎯 Classification Breakdown")
            class_counts = df["Classification"].value_counts()
            st.bar_chart(class_counts)

        with col_d2:
            st.markdown("#### 🚨 Top Triggered Threat Indicators")
            all_flags = []
            for r in results:
                for f in r["flagged"]:
                    all_flags.append(f["check"])
            if all_flags:
                flag_series = pd.Series(all_flags).value_counts().head(6)
                st.bar_chart(flag_series)
            else:
                st.write("No threat flags triggered across scanned dataset.")

        st.markdown("#### 📑 Batch Audit Log")
        st.dataframe(df, use_container_width=True)

