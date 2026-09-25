"""
PhishGuard — FastAPI Backend Server for Chrome Extension
Provides REST APIs for live email scanning and standalone URL threat analysis,
wrapping the existing PhishGuard detection engine without altering its core logic.
"""

import os
import re
from typing import List, Union, Optional, Dict, Any
from urllib.parse import urlparse

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Import existing detection engine modules (Zero modification to engine/)
from engine import parser, rules, scorer, explainer, reputation

app = FastAPI(
    title="PhishGuard Security API",
    description="Explainable Email Phishing & URL Threat Intelligence API for Chrome Extension",
    version="1.0.0"
)

# CRITICAL: Enable CORS for Chrome Extension requests
# Allows requests from chrome-extension:// origins and mail.google.com
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class LinkItem(BaseModel):
    text: Optional[str] = ""
    href: str

class EmailScanRequest(BaseModel):
    sender: str = Field(default="", description="From header or display name + email")
    subject: str = Field(default="", description="Email subject line")
    body: str = Field(default="", description="Visible email body text extracted from DOM")
    links: List[Union[str, Dict[str, Any], LinkItem]] = Field(
        default_factory=list,
        description="List of URLs or link objects extracted from open email"
    )

class UrlScanRequest(BaseModel):
    url: str = Field(..., description="Target URL to inspect for phishing/spoofing threats")


# ---------------------------------------------------------------------------
# Health & Info Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
@app.get("/health")
def health_check():
    """Health check endpoint to verify backend connectivity from extension."""
    return {
        "status": "ok",
        "service": "PhishGuard Security API Server",
        "version": "1.0.0",
        "active_rules": [
            "SPF/DKIM/DMARC Forensics",
            "Display Name Impersonation",
            "Reply-To Mismatch",
            "Typosquat / Lookalike Domain Matcher",
            "URL Shortener Detection",
            "IP-as-URL Detection",
            "Href vs Text Discrepancy",
            "Local Threat Blocklist/Allowlist",
            "Urgency / Social Engineering NLP"
        ]
    }


# ---------------------------------------------------------------------------
# Email Scanning Endpoint
# ---------------------------------------------------------------------------

@app.post("/scan-email")
def scan_email(request: EmailScanRequest):
    """
    Accepts DOM-extracted email parameters, formats them into the standard
    'parsed' dict expected by engine.scorer, executes all forensic rules,
    and attaches plain-English explainability summaries.
    """
    try:
        sender_raw = request.sender.strip()
        subject_raw = request.subject.strip()
        body_raw = request.body.strip()

        # Extract domain and display name using existing parser helpers
        from_domain = parser.extract_domain(sender_raw)
        display_name = parser.extract_display_name(sender_raw)

        # Process extracted links into structured pairs and unique URL list
        urls_set = set()
        html_links = []

        for link in request.links:
            if isinstance(link, str):
                u = link.strip()
                if u.startswith("http://") or u.startswith("https://"):
                    urls_set.add(u)
                    html_links.append({"text": u, "href": u})
            elif isinstance(link, dict):
                href = str(link.get("href", "")).strip()
                text = str(link.get("text", "")).strip()
                if href.startswith("http://") or href.startswith("https://"):
                    urls_set.add(href)
                    html_links.append({"text": text, "href": href})
            elif hasattr(link, "href"):
                href = str(link.href).strip()
                text = str(link.text or "").strip()
                if href.startswith("http://") or href.startswith("https://"):
                    urls_set.add(href)
                    html_links.append({"text": text, "href": href})

        # Also extract any plaintext URLs in the body
        body_urls = re.findall(r'https?://[^\s"\'<>]+', body_raw)
        for bu in body_urls:
            urls_set.add(bu)

        # Construct parsed dictionary compatible with existing engine/
        # NOTE: Live DOM-scraped emails do not include raw RFC headers (SPF/DKIM).
        # We pass auth_results="" and engine/ handles it gracefully.
        parsed = {
            "from": sender_raw,
            "reply_to": sender_raw,
            "to": "",
            "subject": subject_raw,
            "date": "Scanned live from Gmail",
            "auth_results": "",  # Unavailable in client DOM view
            "received": [],
            "body": body_raw,
            "plain_content": body_raw,
            "html_content": "",
            "urls": sorted(list(urls_set)),
            "html_links": html_links,
            "from_domain": from_domain,
            "reply_to_domain": from_domain,
            "display_name": display_name
        }

        # Run through existing scoring engine
        score_result = scorer.score_email(parsed)

        # Generate explainability (Gemini AI with deterministic rule fallback)
        explanation_data = explainer.explain(
            score_result.get("evidence", []),
            score_result.get("classification", "Safe"),
            parsed
        )

        # Compile plain reasons list
        flagged_items = score_result.get("flagged", [])
        reasons = [f.get("explanation", "") for f in flagged_items if f.get("explanation")]
        if not reasons and score_result.get("classification") == "Safe":
            reasons = ["No suspicious domains, deceptive links, or social engineering indicators detected."]

        return {
            "risk": score_result.get("risk_level", "LOW"),
            "status": score_result.get("classification", "Safe"),
            "score": score_result.get("score", 0),
            "color": score_result.get("color", "#10B981"),
            "reasons": reasons,
            "flagged": flagged_items,
            "category_scores": score_result.get("category_scores", {}),
            "explanation": {
                "summary": explanation_data.get("summary", ""),
                "recommendation": explanation_data.get("recommendation", ""),
                "source": explanation_data.get("source", "Heuristic Engine")
            },
            "meta": {
                "sender": sender_raw,
                "display_name": display_name,
                "from_domain": from_domain,
                "subject": subject_raw,
                "links_scanned": len(parsed["urls"]),
                "auth_headers_available": False,
                "scan_mode": "Chrome Extension DOM Live Scan"
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Email analysis error: {str(e)}")


# ---------------------------------------------------------------------------
# Standalone URL Scanning Endpoint
# ---------------------------------------------------------------------------

@app.post("/scan-url")
def scan_url(request: UrlScanRequest):
    """
    Accepts a single URL and runs it through PhishGuard's URL and domain
    reputation rules: Shortener detection, numeric IP detection, Blocklist,
    Allowlist, and Typosquat/Lookalike domain checks.
    """
    target_url = request.url.strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    # Auto-prefix http if user pasted bare domain
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url_for_parse = "http://" + target_url
    else:
        target_url_for_parse = target_url

    domain = reputation.extract_domain_from_url(target_url_for_parse)
    checks = []

    # 1. URL Shortener check
    if domain in rules.SHORTENER_DOMAINS:
        checks.append({
            "check": "URL Shortener Detected",
            "result": "fail",
            "weight": 15,
            "explanation": f"Domain '{domain}' is a known URL shortener masking the true final destination."
        })

    # 2. Raw IP address URL check
    ip_pattern = re.compile(r'https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?')
    if ip_pattern.search(target_url_for_parse):
        checks.append({
            "check": "IP-Address-as-URL",
            "result": "fail",
            "weight": 20,
            "explanation": f"Target uses a raw numeric IP address instead of a legitimate registered domain name."
        })

    # 3. Blocklist check
    blocklist = reputation.load_blocklist()
    if domain in blocklist:
        checks.append({
            "check": "Domain Blocklist Match",
            "result": "fail",
            "weight": 35,
            "explanation": f"Domain '{domain}' matched threat intelligence blocklist: {blocklist[domain]}."
        })

    # 4. Allowlist & Lookalike check
    allowlist = reputation.load_allowlist()
    if domain in allowlist:
        checks.append({
            "check": "Domain Allowlist",
            "result": "pass",
            "weight": -20,
            "explanation": f"Domain '{domain}' is a verified legitimate organization on the safe allowlist (-20 bonus)."
        })
    else:
        # Check lookalike domain impersonation
        lookalike_check = reputation.check_lookalike_reputation(domain, allowlist)
        if lookalike_check.get("weight", 0) > 0:
            checks.append(lookalike_check)

    # 5. Suspicious TLD check
    suspicious_tlds = {".zip", ".mov", ".top", ".tk", ".xyz", ".click", ".gq", ".cf", ".work", ".bar", ".rest"}
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            checks.append({
                "check": "High-Risk TLD",
                "result": "fail",
                "weight": 10,
                "explanation": f"Domain uses high-abuse top-level domain '{tld}' frequently leveraged in phishing."
            })
            break

    # Calculate aggregate score
    total_raw = sum(c.get("weight", 0) for c in checks)
    total_score = max(0, total_raw)

    # Determine classification
    is_blocked = any(c.get("check") == "Domain Blocklist Match" for c in checks)
    if is_blocked or total_score >= 30:
        classification = "Phishing"
        risk_level = "CRITICAL"
        color = "#EF4444"
    elif total_score >= 15:
        classification = "Suspicious"
        risk_level = "MODERATE"
        color = "#F59E0B"
    else:
        classification = "Safe"
        risk_level = "LOW"
        color = "#10B981"

    flagged = [c for c in checks if c.get("weight", 0) > 0]
    reasons = [c.get("explanation", "") for c in flagged]
    if not reasons:
        reasons = ["URL passed all structure, blocklist, and typosquatting security checks."]

    # Plain-English explanation
    if classification == "Phishing":
        explanation = f"CRITICAL THREAT: '{target_url}' presents severe security risks. " + " ".join(reasons)
        recommendation = "DO NOT open this link or submit any passwords, credentials, or personal information."
    elif classification == "Suspicious":
        explanation = f"CAUTION: '{target_url}' triggered anomalous security indicators. " + " ".join(reasons)
        recommendation = "Proceed with caution. Verify the sender/destination through independent channels before clicking."
    else:
        explanation = f"'{target_url}' appears clean with no known threat flags or impersonation indicators."
        recommendation = "Standard safety applies. Always ensure HTTPS encryption before entering sensitive details."

    return {
        "url": target_url,
        "domain": domain,
        "status": classification,
        "risk": risk_level,
        "score": total_score,
        "color": color,
        "reasons": reasons,
        "evidence": checks,
        "flagged": flagged,
        "explanation": {
            "summary": explanation,
            "recommendation": recommendation,
            "source": "PhishGuard URL Intelligence"
        }
    }


# ---------------------------------------------------------------------------
# Local Server Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Starting PhishGuard API Server on http://127.0.0.1:8000 ...")
    uvicorn.run("api_server:app", host="127.0.0.1", port=8000, reload=True)
