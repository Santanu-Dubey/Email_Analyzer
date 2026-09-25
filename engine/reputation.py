import os
import csv
import difflib
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
BLOCKLIST_PATH = os.path.join(DATA_DIR, "blocklist.csv")
ALLOWLIST_PATH = os.path.join(DATA_DIR, "allowlist.csv")

def load_allowlist() -> set:
    """Load trusted domains from allowlist.csv."""
    allowlist = set()
    if os.path.exists(ALLOWLIST_PATH):
        try:
            with open(ALLOWLIST_PATH, mode="r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    domain = row.get("domain", "").strip().lower()
                    if domain:
                        allowlist.add(domain)
        except Exception:
            pass
    # Fallback standard trusted domains if file is empty
    if not allowlist:
        allowlist = {"google.com", "microsoft.com", "apple.com", "stateuniv.edu", "paypal.com", "amazon.com"}
    return allowlist

def load_blocklist() -> dict:
    """Load known malicious domains and reasons from blocklist.csv."""
    blocklist = {}
    if os.path.exists(BLOCKLIST_PATH):
        try:
            with open(BLOCKLIST_PATH, mode="r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    domain = row.get("domain", "").strip().lower()
                    reason = row.get("reason", "Flagged malicious domain").strip()
                    if domain:
                        blocklist[domain] = reason
        except Exception:
            pass
    return blocklist

def extract_domain_from_url(url: str) -> str:
    """Extract host/domain from a URL string."""
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc or parsed.path.split('/')[0]
        # remove port if any
        netloc = netloc.split(':')[0]
        return netloc.lower().strip()
    except Exception:
        return ""

def check_domains(parsed: dict) -> list:
    """
    Check domains from sender, reply-to, and URLs against blocklist and allowlist.
    Returns list of check results.
    """
    results = []
    blocklist = load_blocklist()
    allowlist = load_allowlist()

    from_domain = parsed.get("from_domain", "").lower()
    reply_domain = parsed.get("reply_to_domain", "").lower()

    # Collect all domains from URLs
    url_domains = set()
    for u in parsed.get("urls", []):
        d = extract_domain_from_url(u)
        if d:
            url_domains.add(d)

    all_domains = set()
    if from_domain:
        all_domains.add(from_domain)
    if reply_domain:
        all_domains.add(reply_domain)
    all_domains.update(url_domains)

    # 1. Blocklist check
    blocked_found = []
    for d in all_domains:
        if d in blocklist:
            blocked_found.append((d, blocklist[d]))

    if blocked_found:
        details = ", ".join([f"{d} ({reason})" for d, reason in blocked_found])
        results.append({
            "check": "Domain Blocklist Match",
            "result": "fail",
            "weight": 25,
            "explanation": f"Domain matched known threat intelligence blocklist: {details}."
        })
    else:
        results.append({
            "check": "Domain Blocklist Match",
            "result": "pass",
            "weight": 0,
            "explanation": "No domains matched local threat blocklist."
        })

    # 2. Allowlist check (negative weight reduction if sender is verified allowlisted)
    if from_domain in allowlist:
        results.append({
            "check": "Domain Allowlist",
            "result": "pass",
            "weight": -20,
            "explanation": f"Sender domain '{from_domain}' is on the verified safe allowlist (-20 bonus)."
        })
    else:
        results.append({
            "check": "Domain Allowlist",
            "result": "neutral",
            "weight": 0,
            "explanation": f"Sender domain '{from_domain}' is not on the local allowlist."
        })

    return results

def check_lookalike_reputation(from_domain: str, allowlist: set, threshold: float = 0.75) -> dict:
    """Check if from_domain is suspiciously similar to any allowlisted brand domain."""
    if not from_domain or from_domain in allowlist:
        return {"check": "Lookalike / Typosquat Domain", "result": "pass", "weight": 0, "explanation": "Domain is exact match or not lookalike."}

    # Extract base label (e.g. 'stateuniv' from 'stateuniv.edu' or 'm1crosoft-office' from 'm1crosoft-office.com')
    parts = from_domain.split('.')
    from_base = parts[0] if len(parts) > 1 else from_domain

    for trusted in allowlist:
        trusted_base = trusted.split('.')[0]
        # Similarity of full domain
        ratio_full = difflib.SequenceMatcher(None, from_domain, trusted).ratio()
        # Similarity of domain brand name
        ratio_base = difflib.SequenceMatcher(None, from_base, trusted_base).ratio()

        # Check leetspeak/typosquat substring patterns (e.g. m1crosoft, coll3ge, stateunlv)
        is_suspicious_sub = (
            (trusted_base in from_domain and from_domain != trusted) or
            (from_base in trusted and len(from_base) >= 4)
        )

        max_ratio = max(ratio_full, ratio_base)
        if (max_ratio >= threshold and max_ratio < 1.0) or is_suspicious_sub:
            return {
                "check": "Lookalike / Typosquat Domain",
                "result": "fail",
                "weight": 20,
                "explanation": f"Sender domain '{from_domain}' appears to impersonate trusted domain '{trusted}' (similarity: {max_ratio:.2f})."
            }

    return {
        "check": "Lookalike / Typosquat Domain",
        "result": "pass",
        "weight": 0,
        "explanation": "No typosquatting or lookalike domain characteristics detected."
    }
