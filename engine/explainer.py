import os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

def get_api_key() -> str:
    """Retrieve Gemini API key from environment variables."""
    return os.getenv("GEMINI_API_KEY", "").strip()

def fallback_explanation(flagged: list, classification: str, subject: str = "") -> dict:
    """
    Generate deterministic, explainable plain-English explanation and recommendation
    when Gemini API is not configured or unavailable.
    """
    if classification == "Safe" or not flagged:
        return {
            "summary": "This email passed standard authentication and heuristic security checks. No suspicious indicators, domain spoofs, or deceptive links were identified.",
            "recommendation": "While this email appears legitimate, always practice standard cyber hygiene before clicking unexpected attachments or entering credentials.",
            "source": "Heuristic Engine (Rule-based Fallback)"
        }

    reasons = [f["explanation"] for f in flagged[:4]]
    reasons_str = " ".join(reasons)

    if classification == "Phishing":
        summary = (
            f"This email was classified as HIGH RISK PHISHING ({len(flagged)} threat indicators detected). "
            f"Key findings include: {reasons_str}"
        )
        recommendation = (
            "DO NOT click any links, open attachments, or reply to this sender. "
            "Immediately report this message to your security operations team or IT helpdesk and delete it."
        )
    else:  # Suspicious
        summary = (
            f"This email was classified as SUSPICIOUS due to anomalous indicators: {reasons_str}"
        )
        recommendation = (
            "Exercise extreme caution. Do not click embedded links directly. "
            "Verify the authenticity of this request through a separate, known-trusted communication channel."
        )

    return {
        "summary": summary,
        "recommendation": recommendation,
        "source": "Heuristic Engine (Rule-based Fallback)"
    }

def explain(evidence: list, classification: str, parsed: dict = None) -> dict:
    """
    Generate plain-English explanation + safety recommendation using Gemini 2.5 Flash,
    with an immediate fallback to rule-based analysis on failure or missing API key.
    """
    flagged = [e for e in evidence if e.get("weight", 0) > 0]
    subject = parsed.get("subject", "") if parsed else ""
    from_addr = parsed.get("from", "") if parsed else ""

    api_key = get_api_key()
    if not api_key:
        return fallback_explanation(flagged, classification, subject)

    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.5-flash")

        flagged_summary = "; ".join([f"{f['check']}: {f['explanation']}" for f in flagged])
        if not flagged_summary:
            flagged_summary = "All security checks passed (SPF/DKIM/DMARC valid, no impersonation, clean URLs)."

        prompt = (
            f"You are an expert email cybersecurity analyst explaining security findings to an everyday user.\n"
            f"Email Subject: '{subject}'\n"
            f"From Header: '{from_addr}'\n"
            f"Classification: {classification}\n"
            f"Security Evidence Flags: {flagged_summary}\n\n"
            f"Task: Write a concise 2-sentence plain-English explanation of why this email is classified as {classification}, "
            f"followed by 1 clear, actionable safety recommendation for the user. Avoid technical jargon like regex or heuristics."
        )

        resp = model.generate_content(prompt, request_options={"timeout": 6})
        response_text = resp.text.strip()

        # Split summary and recommendation if clearly delimited, or format cleanly
        parts = response_text.split("Recommendation:")
        if len(parts) == 2:
            summary = parts[0].replace("Explanation:", "").strip()
            recommendation = parts[1].strip()
        else:
            summary = response_text
            recommendation = "Do not interact with suspicious links or provide credentials. Verify through official channels."

        return {
            "summary": summary,
            "recommendation": recommendation,
            "source": "Gemini 2.5 Flash AI"
        }
    except Exception:
        # Seamlessly fallback if API error, quota, timeout, or network issue
        return fallback_explanation(flagged, classification, subject)
