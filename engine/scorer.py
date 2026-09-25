from engine import rules, reputation

def score_email(parsed: dict) -> dict:
    """
    Evaluate all heuristic and threat intelligence rules against the parsed email.
    Computes total threat score, assigns classification (Safe, Suspicious, Phishing),
    applies false-positive safeguards for credential/threat phrases, and returns
    a comprehensive forensic evidence breakdown.
    """
    checks = [
        rules.check_spf(parsed),
        rules.check_dkim(parsed),
        rules.check_dmarc(parsed),
        rules.check_reply_to_mismatch(parsed),
        rules.check_display_name(parsed),
        rules.check_brand_impersonation(parsed),
        rules.check_shorteners(parsed),
        rules.check_ip_urls(parsed),
        rules.check_href_mismatch(parsed),
        rules.check_lookalike_domains(parsed),
        rules.check_credential_harvesting(parsed),
        rules.check_account_threat_language(parsed),
        rules.check_urgency_keywords(parsed),
        rules.check_generic_greeting(parsed),
        rules.check_urls_present(parsed),
    ]

    # Add domain reputation checks (blocklist & allowlist)
    checks += reputation.check_domains(parsed)

    # Compute raw total score
    total_raw = sum(c.get("weight", 0) for c in checks)
    total_score = max(0, total_raw)  # Floor at 0 for display

    # Base classification thresholds
    if total_score >= 50:
        classification = "Phishing"
        risk_level = "CRITICAL"
        color = "#EF4444"  # Red
    elif total_score >= 20:
        classification = "Suspicious"
        risk_level = "MODERATE"
        color = "#F59E0B"  # Amber/Orange
    else:
        classification = "Safe"
        risk_level = "LOW"
        color = "#10B981"  # Green

    # -----------------------------------------------------------------------
    # PART C — FALSE POSITIVE SAFEGUARD
    # If the ONLY flagged checks are credential harvesting and/or account threat
    # language (or missing/unconfigured auth headers without explicit fail),
    # cap the classification at "Suspicious", never "Phishing".
    # Require at least one corroborating signal (explicit auth failure,
    # brand/domain impersonation, or suspicious URL) for a "Phishing" verdict.
    # -----------------------------------------------------------------------
    explicit_auth_failures = [
        c for c in checks
        if c["check"] in ["SPF Authentication", "DKIM Signature", "DMARC Alignment"]
        and c.get("result") == "fail"
    ]

    identity_flags = [
        c for c in checks
        if c["check"] in [
            "From vs Reply-To Mismatch",
            "Display Name Impersonation",
            "Brand Impersonation",
            "Lookalike / Typosquat Domain"
        ] and c.get("weight", 0) > 0
    ]

    link_flags = [
        c for c in checks
        if c["check"] in [
            "URL Shortener Detected",
            "IP-Address-as-URL",
            "Href vs Display Text Mismatch",
            "Domain Blocklist Match"
        ] and c.get("weight", 0) > 0
    ]

    has_corroborating_signal = bool(explicit_auth_failures or identity_flags or link_flags)

    if classification == "Phishing" and not has_corroborating_signal:
        classification = "Suspicious"
        risk_level = "MODERATE"
        color = "#F59E0B"

    # Filter triggered flags (positive risk weight)
    flagged = [c for c in checks if c.get("weight", 0) > 0]
    passed = [c for c in checks if c.get("weight", 0) <= 0 and c.get("result") == "pass"]

    # Category breakdowns for deep explainability
    auth_checks = [c for c in checks if c["check"] in ["SPF Authentication", "DKIM Signature", "DMARC Alignment"]]
    identity_checks = [c for c in checks if c["check"] in ["From vs Reply-To Mismatch", "Display Name Impersonation", "Brand Impersonation", "Lookalike / Typosquat Domain"]]
    content_checks = [c for c in checks if c["check"] in ["Urgency & Psychological Pressure", "Generic Salutation", "Credential Harvesting", "Account Threat & Consequence"]]
    link_checks = [c for c in checks if c["check"] in ["URL Shortener Detected", "IP-Address-as-URL", "Href vs Display Text Mismatch", "Domain Blocklist Match"]]

    category_scores = {
        "Authentication": sum(c.get("weight", 0) for c in auth_checks),
        "Identity & Sender": sum(c.get("weight", 0) for c in identity_checks),
        "Content & Pressure": sum(c.get("weight", 0) for c in content_checks),
        "Links & Threat Intel": sum(c.get("weight", 0) for c in link_checks),
    }

    return {
        "score": total_score,
        "raw_score": total_raw,
        "classification": classification,
        "risk_level": risk_level,
        "color": color,
        "evidence": checks,
        "flagged": flagged,
        "passed": passed,
        "category_scores": category_scores,
        "from_domain": parsed.get("from_domain", "Unknown"),
        "subject": parsed.get("subject", "(No Subject)"),
        "date": parsed.get("date", "Unknown"),
        "url_count": len(parsed.get("urls", [])),
    }

