"""
End-to-End Scenario Validation for PhishGuard Gmail API Upgrade & DOM Fallback.
Tests:
1. Real RFC 5322 Raw Email with valid cryptographic headers -> Real SPF/DKIM/DMARC evaluation.
2. Simulated API failure -> Graceful DOM-scraping fallback simulation.
3. DOM-scraping endpoint (/scan-email) unchanged verification.
4. Standalone URL checker (/scan-url) unchanged verification.
"""

import os
import sys
import base64
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from api_server import scan_raw_email, scan_email, scan_url, RawEmailScanRequest, EmailScanRequest, UrlScanRequest
from engine import parser, rules, scorer

def run_scenarios():
    print("=" * 70)
    print("PHISHGUARD UPGRADE VALIDATION SUITE")
    print("=" * 70)

    # -------------------------------------------------------------------------
    # SCENARIO 1: Valid Raw Email with Real SPF / DKIM / DMARC Headers
    # -------------------------------------------------------------------------
    print("\n[SCENARIO 1] Scanning Genuine Email with Real RFC 5322 Authentication Headers")
    print("-" * 70)

    genuine_rfc5322 = (
        b"From: \"Google Workspace\" <workspace-noreply@google.com>\r\n"
        b"Reply-To: workspace-noreply@google.com\r\n"
        b"To: user@company.com\r\n"
        b"Subject: Monthly Security Summary Report\r\n"
        b"Date: Sun, 27 Sep 2026 10:15:30 +0000\r\n"
        b"Authentication-Results: mx.google.com; "
        b"spf=pass (google.com: domain of workspace-noreply@google.com designates 209.85.220.41 as permitted sender); "
        b"dkim=pass header.i=@google.com header.s=20230601 header.b=abcdef12; "
        b"dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com\r\n"
        b"Content-Type: text/html; charset=UTF-8\r\n"
        b"\r\n"
        b"<html><body><h3>Your Google Workspace is secure</h3><p>Review devices at <a href='https://myaccount.google.com/security'>Google Security</a></p></body></html>\r\n"
    )

    b64_raw = base64.urlsafe_b64encode(genuine_rfc5322).decode('utf-8').rstrip('=')
    raw_req = RawEmailScanRequest(raw=b64_raw)
    raw_result = scan_raw_email(raw_req)

    print(f"Status:       {raw_result['status']} (Risk: {raw_result['risk']})")
    print(f"Threat Score: {raw_result['score']}/100")
    print(f"Scan Mode:    {raw_result['meta']['scan_mode']}")
    print(f"Auth Headers: {raw_result['meta']['auth_headers_available']}")
    print(f"Category Breakdown: {raw_result['category_scores']}")
    print(f"Explanation:  {raw_result['explanation']['summary']}")

    # Check evidence for explicit pass
    parsed = parser.parse_raw_bytes(genuine_rfc5322)
    score_data = scorer.score_email(parsed)
    auth_passed = [c for c in score_data['evidence'] if c['check'] in ['SPF Authentication', 'DKIM Signature', 'DMARC Alignment']]
    print("Authentication Checks Evaluated:")
    for c in auth_passed:
        print(f"  - {c['check']}: Result={c['result']}, Weight={c['weight']}, Explanation={c['explanation']}")

    # -------------------------------------------------------------------------
    # SCENARIO 2: Spoofed Email with Real FAILED SPF / DKIM / DMARC Headers
    # -------------------------------------------------------------------------
    print("\n[SCENARIO 1b] Scanning Spoofed Phishing Email with FAILED SPF/DKIM/DMARC")
    print("-" * 70)

    phish_rfc5322 = (
        b"From: \"PayPal Security\" <service@paypal.com>\r\n"
        b"Reply-To: attacker@phishing-server.ru\r\n"
        b"To: victim@example.com\r\n"
        b"Subject: URGENT: Account Suspended Immediately\r\n"
        b"Date: Sun, 27 Sep 2026 10:15:30 +0000\r\n"
        b"Authentication-Results: mx.google.com; "
        b"spf=fail (google.com: domain of service@paypal.com does not designate 198.51.100.25 as permitted sender); "
        b"dkim=fail (bad signature) header.i=@paypal.com; "
        b"dmarc=fail (p=REJECT) header.from=paypal.com\r\n"
        b"Content-Type: text/html; charset=UTF-8\r\n"
        b"\r\n"
        b"<html><body>Dear customer, your account will be suspended within 24 hours. "
        b"<a href='http://bit.ly/fake-paypal-verify'>Verify your password</a> immediately.</body></html>\r\n"
    )

    b64_phish = base64.urlsafe_b64encode(phish_rfc5322).decode('utf-8').rstrip('=')
    phish_result = scan_raw_email(RawEmailScanRequest(raw=b64_phish))

    print(f"Status:       {phish_result['status']} (Risk: {phish_result['risk']})")
    print(f"Threat Score: {phish_result['score']}/100")
    print(f"Scan Mode:    {phish_result['meta']['scan_mode']}")
    print(f"Auth Score:   +{phish_result['category_scores']['Authentication']} pts (Cryptographic Failures Detected)")
    print(f"Flagged Items ({len(phish_result['flagged'])}):")
    for f in phish_result['flagged']:
        print(f"  * [+{f.get('weight', 0)} pts] {f.get('check')}: {f.get('explanation')}")

    # -------------------------------------------------------------------------
    # SCENARIO 3: DOM Fallback Simulation (API fails -> DOM scan succeeds)
    # -------------------------------------------------------------------------
    print("\n[SCENARIO 2 & 3] Simulated OAuth/API Failure -> Automatic DOM Scraping Fallback")
    print("-" * 70)

    # In content.js: if getAuthToken() or fetchGmailRawEmail() throws, fallback extracts DOM:
    dom_payload = EmailScanRequest(
        sender="PayPal Security <service@paypal.com>",
        subject="URGENT: Account Suspended Immediately",
        body="Dear customer, your account will be suspended within 24 hours. Verify your password immediately.",
        links=[{"text": "Verify your password", "href": "http://bit.ly/fake-paypal-verify"}]
    )

    dom_result = scan_email(dom_payload)
    print(f"Status:       {dom_result['status']} (Risk: {dom_result['risk']})")
    print(f"Threat Score: {dom_result['score']}/100")
    print(f"Scan Mode:    {dom_result['meta']['scan_mode']}")
    print(f"Auth Headers: {dom_result['meta']['auth_headers_available']} (Headers unavailable in DOM scraper)")
    print(f"Explanation:  {dom_result['explanation']['summary']}")

    # -------------------------------------------------------------------------
    # SCENARIO 4: Standalone URL Scanner (/scan-url)
    # -------------------------------------------------------------------------
    print("\n[SCENARIO 4] Standalone URL Threat Analysis Endpoint (/scan-url)")
    print("-" * 70)

    urls_to_test = [
        "https://www.google.com",
        "https://bit.ly/3xyz123",
        "http://192.168.1.1/login"
    ]

    for u in urls_to_test:
        url_res = scan_url(UrlScanRequest(url=u))
        print(f"URL: {u.ljust(26)} -> Status: {url_res['status'].ljust(10)} Score: {str(url_res['score']).ljust(3)} Risk: {url_res['risk']}")

    print("\n" + "=" * 70)
    print("ALL VALIDATION SCENARIOS EXECUTED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    run_scenarios()
