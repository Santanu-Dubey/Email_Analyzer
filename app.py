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
    /* Main container styling */
    .main-header {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(135deg, #3B82F6 0%, #8B5CF6 50%, #EC4899 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #94A3B8;
        margin-bottom: 1.5rem;
    }
    .card {
        background: #1E293B;
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 1.25rem;
        margin-bottom: 1rem;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    }
    .badge {
        display: inline-block;
        padding: 0.25rem 0.6rem;
        border-radius: 9999px;
        font-size: 0.8rem;
        font-weight: 600;
        margin-right: 0.4rem;
    }
    .badge-safe { background-color: rgba(16, 185, 129, 0.2); color: #10B981; border: 1px solid #10B981; }
    .badge-suspicious { background-color: rgba(245, 158, 11, 0.2); color: #F59E0B; border: 1px solid #F59E0B; }
    .badge-phish { background-color: rgba(239, 68, 68, 0.2); color: #EF4444; border: 1px solid #EF4444; }
    .evidence-item {
        background: #0F172A;
        border-left: 4px solid #EF4444;
        padding: 0.75rem 1rem;
        margin: 0.5rem 0;
        border-radius: 0 8px 8px 0;
    }
    .evidence-pass {
        background: #0F172A;
        border-left: 4px solid #10B981;
        padding: 0.5rem 1rem;
        margin: 0.3rem 0;
        border-radius: 0 8px 8px 0;
    }
</style>
""", unsafe_allow_html=True)

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
st.markdown('<div class="main-header">🛡️ PhishGuard — Explainable Email Analyzer</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Inspect raw <code>.eml</code> messages, uncover spoofing vectors, and examine transparent evidence breakdowns.</div>', unsafe_allow_html=True)

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
            if classification == "Phishing":
                badge_class = "badge-phish"
                header_icon = "🚨"
            elif classification == "Suspicious":
                badge_class = "badge-suspicious"
                header_icon = "⚠️"
            else:
                badge_class = "badge-safe"
                header_icon = "✅"

            with st.container():
                st.markdown(f"""
                <div style="background:#1E293B; border-radius:12px; padding:1.2rem; border-left: 6px solid {color}; margin-bottom:1.5rem;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <h3 style="margin:0; color:#F8FAFC;">{header_icon} {fname}</h3>
                        <div>
                            <span class="badge {badge_class}">{classification.upper()}</span>
                            <span style="font-weight:700; color:#CBD5E1; font-size:1.1rem;">Score: {score}/100</span>
                        </div>
                    </div>
                    <p style="color:#94A3B8; margin-top:0.4rem; margin-bottom:0.2rem;">
                        <strong>Subject:</strong> {parsed.get('subject') or '(No Subject)'} | 
                        <strong>From:</strong> <code>{parsed.get('from')}</code>
                    </p>
                </div>
                """, unsafe_allow_html=True)

                col_left, col_right = st.columns([3, 2])

                with col_left:
                    # Plain English explanation card
                    st.markdown("#### 💡 Explainable AI Analysis & Guidance")
                    st.info(f"**Explanation:** {explanation['summary']}\n\n**🛡️ Recommended Action:** {explanation['recommendation']}\n\n*Source: {explanation.get('source', 'Engine')}*")

                    # Flagged evidence
                    st.markdown(f"#### ⚠️ Triggered Threat Indicators ({len(flagged)})")
                    if flagged:
                        for f in flagged:
                            st.markdown(f"""
                            <div class="evidence-item">
                                <div style="display:flex; justify-content:space-between;">
                                    <strong>{f['check']}</strong>
                                    <span style="color:#EF4444; font-weight:bold;">+{f['weight']} pts</span>
                                </div>
                                <div style="color:#CBD5E1; font-size:0.9rem; margin-top:0.2rem;">{f['explanation']}</div>
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
                            st.markdown(f"""
                            <div class="evidence-pass">
                                <span style="color:#10B981;">✔ <strong>{p['check']}</strong></span>: {p['explanation']}
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
        m1.metric("Total Scanned", total_scanned)
        m2.metric("Phishing Detected", phish_count, delta=f"{(phish_count/total_scanned)*100:.0f}%", delta_color="inverse")
        m3.metric("Suspicious", suspicious_count)
        m4.metric("Safe / Legitimate", safe_count)
        m5.metric("Avg Threat Score", f"{avg_score:.1f}/100")

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
