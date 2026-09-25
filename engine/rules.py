import re
from urllib.parse import urlparse
from engine.reputation import load_allowlist, check_lookalike_reputation, extract_domain_from_url

# Known URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "rebrand.ly",
    "clck.ru", "v.gd", "t.ly", "s.id"
}

# Known legitimate Email Service Provider (ESP) click-tracking & redirect domains
KNOWN_ESP_DOMAINS = {
    "sendgrid.net", "mailchimp.com", "mcusercontent.com", "list-manage.com",
    "constantcontact.com", "hubspotemail.net", "hs-sites.com",
    "mailgun.org", "sparkpostmail.com", "salesforce.com", "exacttarget.com",
    "campaign-archive.com", "click.email", "clicks.mlsend.com"
}

def is_esp_domain(domain: str) -> bool:
    """Check if domain matches or is a subdomain of a known ESP tracking service."""
    if not domain:
        return False
    domain = domain.lower()
    if domain in KNOWN_ESP_DOMAINS:
        return True
    return any(domain.endswith("." + esp) for esp in KNOWN_ESP_DOMAINS)

# High-risk urgency & social engineering keyword phrases
URGENCY_KEYWORDS = [
    "urgent", "immediately", "immediate action", "within 24 hours", "within 48 hours",
    "account suspended", "account deactivation", "unauthorized login", "security alert",
    "password expired", "verify your account", "verify identity", "action required",
    "payroll failure", "direct deposit", "suspended immediately", "quota exceeded",
    "compromised", "restrict access", "permanently locked", "critical alert",
    "unrecognized device", "failure to respond", "restore access"
]

# Sensitive brand/authority keywords for display name spoofing
AUTHORITY_KEYWORDS = [
    "it support", "helpdesk", "security team", "admin center", "administrator",
    "registrar", "payroll", "human resources", "compliance", "billing",
    "paypal", "microsoft", "google", "apple", "amazon", "bank", "chase",
    "wells fargo", "campus security", "student services", "technical support"
]

# Known Brand to Legitimate Domain mapping for Brand Impersonation detection
KNOWN_BRANDS = {
    "gmail": "google.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "apple": "apple.com"
}

# Sensitive credential harvesting phrases
CREDENTIAL_HARVESTING_PHRASES = [
    "verify your password",
    "confirm your login",
    "verify your identity",
    "enter your credentials",
    "update your payment",
    "confirm your account details",
    "confirm your password",
    "enter your password",
    "update your credentials",
    "re-verify your banking",
    "banking password",
    "re-authorize your direct deposit",
    "verify your credentials",
    "submit your credentials",
    "confirm your identity",
    "credential details"
]

# Account threat and consequence coercion phrases (distinct from generic urgency)
ACCOUNT_THREAT_PHRASES = [
    "account will be suspended",
    "account has been locked",
    "unusual activity detected",
    "access will be restricted",
    "your account will be closed",
    "immediate action required",
    "account will be permanently suspended",
    "account will be permanently locked",
    "account access has been temporarily restricted",
    "account access has been restricted",
    "access will be permanently suspended",
    "access will be terminated",
    "account deactivation",
    "incoming mail termination",
    "messages will be suspended",
    "unauthorized login attempts",
    "unauthorized login attempt",
    "suspicious login detected",
    "suspicious activity detected"
]

# Generic non-personalized greetings
GENERIC_GREETINGS = [
    r"\bdear\s+(?:customer|user|client|member|account\s+holder|sir|madam|sir/madam|subscriber|student|employee|resident)\b",
    r"\bvalued\s+(?:customer|user|client|member|partner)\b",
    r"\battention\s+(?:account\s+holder|user|customer)\b"
]

def check_spf(parsed: dict) -> dict:
    """
    Check SPF authentication results from email headers.
    Distinguishes explicit fail (weight 20) vs pass (weight 0) vs unavailable/none (weight 0).
    """
    auth = parsed.get("auth_results", "").lower()
    if "spf=fail" in auth or "spf=hardfail" in auth:
        return {
            "check": "SPF Authentication",
            "result": "fail",
            "weight": 20,
            "explanation": "Sender domain explicitly failed SPF authentication (unauthorized mail server IP)."
        }
    elif "spf=softfail" in auth:
        return {
            "check": "SPF Authentication",
            "result": "fail",
            "weight": 10,
            "explanation": "SPF authentication returned softfail (suspicious sending IP address)."
        }
    elif "spf=pass" in auth:
        return {
            "check": "SPF Authentication",
            "result": "pass",
            "weight": 0,
            "explanation": "SPF authentication passed successfully."
        }
    return {
        "check": "SPF Authentication",
        "result": "none",
        "weight": 0,
        "explanation": "SPF header unavailable (not exposed by this scan method or unconfigured)."
    }

def check_dkim(parsed: dict) -> dict:
    """
    Check DKIM cryptographic signature verification.
    Distinguishes explicit fail (weight 20) vs pass (weight 0) vs unavailable/none (weight 0).
    """
    auth = parsed.get("auth_results", "").lower()
    if "dkim=fail" in auth:
        return {
            "check": "DKIM Signature",
            "result": "fail",
            "weight": 20,
            "explanation": "DKIM cryptographic signature verification explicitly failed (possible header/body tampering)."
        }
    elif "dkim=pass" in auth:
        return {
            "check": "DKIM Signature",
            "result": "pass",
            "weight": 0,
            "explanation": "DKIM cryptographic signature verified successfully."
        }
    return {
        "check": "DKIM Signature",
        "result": "none",
        "weight": 0,
        "explanation": "DKIM signature header unavailable (not exposed by this scan method or unverified)."
    }

def check_dmarc(parsed: dict) -> dict:
    """
    Check DMARC policy alignment.
    Distinguishes explicit fail (weight 15) vs pass (weight 0) vs unavailable/none (weight 0).
    """
    auth = parsed.get("auth_results", "").lower()
    if "dmarc=fail" in auth:
        return {
            "check": "DMARC Alignment",
            "result": "fail",
            "weight": 15,
            "explanation": "DMARC domain alignment policy explicitly failed."
        }
    elif "dmarc=pass" in auth:
        return {
            "check": "DMARC Alignment",
            "result": "pass",
            "weight": 0,
            "explanation": "DMARC policy alignment passed successfully."
        }
    return {
        "check": "DMARC Alignment",
        "result": "none",
        "weight": 0,
        "explanation": "DMARC record unavailable (not exposed by this scan method or absent)."
    }

def check_reply_to_mismatch(parsed: dict) -> dict:
    """Detect From vs Reply-To address/domain discrepancies."""
    from_domain = parsed.get("from_domain", "").lower()
    reply_domain = parsed.get("reply_to_domain", "").lower()

    if reply_domain and from_domain and reply_domain != from_domain:
        return {
            "check": "From vs Reply-To Mismatch",
            "result": "fail",
            "weight": 15,
            "explanation": f"Reply-To domain '{reply_domain}' does not match From domain '{from_domain}', routing responses to external address."
        }
    return {
        "check": "From vs Reply-To Mismatch",
        "result": "pass",
        "weight": 0,
        "explanation": "Reply-To address matches sender domain or is not redirected."
    }

def check_display_name(parsed: dict) -> dict:
    """Detect display name impersonation of trusted brands or departments."""
    display_name = parsed.get("display_name", "").lower()
    from_domain = parsed.get("from_domain", "").lower()

    if not display_name or not from_domain:
        return {
            "check": "Display Name Impersonation",
            "result": "pass",
            "weight": 0,
            "explanation": "No deceptive display name detected."
        }

    matched_keywords = [kw for kw in AUTHORITY_KEYWORDS if kw in display_name]
    if matched_keywords:
        # Check if from_domain clearly matches the claimed brand
        # e.g., display name "PayPal Security" with domain "paypal-alerts-update.com" or "gmail.com"
        first_kw = matched_keywords[0]
        # Clean brand name token (e.g. "paypal" or "microsoft")
        brand_token = first_kw.split()[0]
        if brand_token not in from_domain:
            return {
                "check": "Display Name Impersonation",
                "result": "fail",
                "weight": 10,
                "explanation": f"Display name '{parsed.get('display_name')}' claims authority ('{first_kw}'), but sender domain '{from_domain}' does not match."
            }

    return {
        "check": "Display Name Impersonation",
        "result": "pass",
        "weight": 0,
        "explanation": "Display name aligns with sender identity."
    }

def check_shorteners(parsed: dict) -> dict:
    """Detect presence of URL shortening services hiding final destinations."""
    urls = parsed.get("urls", [])
    found_shorteners = []

    for u in urls:
        domain = extract_domain_from_url(u)
        if domain in SHORTENER_DOMAINS:
            found_shorteners.append(u)

    if found_shorteners:
        return {
            "check": "URL Shortener Detected",
            "result": "fail",
            "weight": 10,
            "explanation": f"Found {len(found_shorteners)} shortened URL(s) masking target destination: {', '.join(found_shorteners[:2])}."
        }
    return {
        "check": "URL Shortener Detected",
        "result": "pass",
        "weight": 0,
        "explanation": "No obfuscated URL shorteners detected."
    }

def check_ip_urls(parsed: dict) -> dict:
    """Detect URLs pointing directly to numeric IP addresses."""
    urls = parsed.get("urls", [])
    ip_pattern = re.compile(r'https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?')
    found_ips = []

    for u in urls:
        match = ip_pattern.search(u)
        if match:
            found_ips.append(match.group(0))

    # Also check plain body
    body = parsed.get("body", "")
    body_ips = ip_pattern.findall(body)
    for bip in body_ips:
        if bip not in found_ips:
            found_ips.append(bip)

    if found_ips:
        return {
            "check": "IP-Address-as-URL",
            "result": "fail",
            "weight": 15,
            "explanation": f"Detected URL using raw numeric IP address instead of domain name: {', '.join(found_ips[:2])}."
        }
    return {
        "check": "IP-Address-as-URL",
        "result": "pass",
        "weight": 0,
        "explanation": "No direct IP address URLs found."
    }

def check_href_mismatch(parsed: dict) -> dict:
    """Detect deceptive links where anchor display text contradicts actual href destination."""
    pairs = parsed.get("html_links", [])
    mismatches = []

    for p in pairs:
        text = p.get("text", "").strip()
        href = p.get("href", "").strip()

        # Check if text looks like a URL or domain name (contains .com, .edu, http, etc.)
        if re.search(r'https?://|[a-zA-Z0-9-]+\.(?:com|edu|org|net|gov|io|biz|info|ac\.in|co\.[a-z]{2})', text, re.IGNORECASE):
            text_domain = extract_domain_from_url(text) if ("http" in text or "/" in text) else text.split('/')[0].strip()
            href_domain = extract_domain_from_url(href)

            # Skip if destination href is a known legitimate ESP tracking/redirect domain (e.g. SendGrid, Mailchimp)
            if href_domain and is_esp_domain(href_domain):
                continue

            if text_domain and href_domain and text_domain.lower() != href_domain.lower():
                mismatches.append(f"Text displays '{text}' but links to '{href_domain}'")

    if mismatches:
        return {
            "check": "Href vs Display Text Mismatch",
            "result": "fail",
            "weight": 15,
            "explanation": f"Deceptive link detected: {mismatches[0]}."
        }
    return {
        "check": "Href vs Display Text Mismatch",
        "result": "pass",
        "weight": 0,
        "explanation": "Link anchor texts match their target destinations or use legitimate ESP tracking."
    }

def check_lookalike_domains(parsed: dict) -> dict:
    """Detect typosquatting or brand impersonation in sender domain."""
    from_domain = parsed.get("from_domain", "")
    allowlist = load_allowlist()
    return check_lookalike_reputation(from_domain, allowlist)

def check_urgency_keywords(parsed: dict) -> dict:
    """Scan subject and body for high-pressure social engineering keywords."""
    text = (parsed.get("subject", "") + " " + parsed.get("body", "")).lower()
    matched = []

    for kw in URGENCY_KEYWORDS:
        if kw in text and kw not in matched:
            matched.append(kw)

    count = min(len(matched), 3)
    if count > 0:
        weight = count * 5  # 5 points per keyword up to max 15
        return {
            "check": "Urgency & Psychological Pressure",
            "result": "fail",
            "weight": weight,
            "explanation": f"Detected {len(matched)} high-urgency / coercion phrase(s): '{', '.join(matched[:3])}' (+{weight} pts)."
        }
    return {
        "check": "Urgency & Psychological Pressure",
        "result": "pass",
        "weight": 0,
        "explanation": "No coercive or urgent social engineering keywords detected."
    }

def check_generic_greeting(parsed: dict) -> dict:
    """Detect impersonal generic greetings typical of bulk phishing campaigns."""
    body = parsed.get("body", "")
    for pattern in GENERIC_GREETINGS:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            return {
                "check": "Generic Salutation",
                "result": "fail",
                "weight": 5,
                "explanation": f"Detected impersonal bulk greeting: '{match.group(0)}'."
            }
    return {
        "check": "Generic Salutation",
        "result": "pass",
        "weight": 0,
        "explanation": "Personalized or standard greeting."
    }

def check_urls_present(parsed: dict) -> dict:
    """Assess overall link count and presence."""
    urls = parsed.get("urls", [])
    if urls:
        return {
            "check": "URL Link Analysis",
            "result": "info",
            "weight": 0,
            "explanation": f"Extracted {len(urls)} distinct link(s) for security inspection."
        }
    return {
        "check": "URL Link Analysis",
        "result": "info",
        "weight": 0,
        "explanation": "No external URLs found in email body."
    }

def check_credential_harvesting(parsed: dict) -> dict:
    """
    Scan email body for sensitive credential harvesting phrases (password, credentials, login verification).
    """
    body = (parsed.get("body", "") + " " + parsed.get("plain_content", "")).lower()
    matched = []
    for phrase in CREDENTIAL_HARVESTING_PHRASES:
        if phrase in body and phrase not in matched:
            matched.append(phrase)

    if matched:
        return {
            "check": "Credential Harvesting",
            "result": "flagged",
            "weight": 15,
            "explanation": f"Detected credential harvesting phrase: '{matched[0]}'."
        }
    return {
        "check": "Credential Harvesting",
        "result": "pass",
        "weight": 0,
        "explanation": "No credential harvesting phrases detected."
    }

def check_account_threat_language(parsed: dict) -> dict:
    """
    Scan subject and body for threat-of-consequence language distinct from generic urgency words.
    """
    text = (parsed.get("subject", "") + " " + parsed.get("body", "") + " " + parsed.get("plain_content", "")).lower()
    matched = []
    for phrase in ACCOUNT_THREAT_PHRASES:
        if phrase in text and phrase not in matched:
            matched.append(phrase)

    if matched:
        return {
            "check": "Account Threat & Consequence",
            "result": "flagged",
            "weight": 10,
            "explanation": f"Detected account threat/consequence language: '{matched[0]}'."
        }
    return {
        "check": "Account Threat & Consequence",
        "result": "pass",
        "weight": 0,
        "explanation": "No coercive account threat or consequence language detected."
    }

def check_brand_impersonation(parsed: dict) -> dict:
    """
    Check if the sender display name or From field claims to be a recognized brand
    while the actual sending domain does NOT match that brand's official domain.
    """
    from_field = f"{parsed.get('display_name', '')} {parsed.get('from', '')}".lower()
    from_domain = parsed.get("from_domain", "").lower()

    if not from_domain:
        return {
            "check": "Brand Impersonation",
            "result": "pass",
            "weight": 0,
            "explanation": "No sender domain available to check brand impersonation."
        }

    for brand, legit_domain in KNOWN_BRANDS.items():
        if re.search(r'\b' + re.escape(brand) + r'\b', from_field):
            # Check domain match: allows exact domain or subdomains (e.g. mail.google.com)
            is_legit = (
                from_domain == legit_domain or
                from_domain.endswith("." + legit_domain) or
                (brand == "gmail" and (from_domain == "gmail.com" or from_domain.endswith(".google.com")))
            )
            if not is_legit:
                return {
                    "check": "Brand Impersonation",
                    "result": "flagged",
                    "weight": 10,
                    "explanation": f"Sender identity claims brand '{brand.title()}', but sending domain '{from_domain}' does not match official domain '{legit_domain}'."
                }

    return {
        "check": "Brand Impersonation",
        "result": "pass",
        "weight": 0,
        "explanation": "Sender identity aligns with recognized brand domain or no brand claim made."
    }
