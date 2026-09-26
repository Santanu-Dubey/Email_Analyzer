import unittest
import base64
from fastapi import HTTPException
from api_server import scan_raw_email, scan_email, scan_url, RawEmailScanRequest, EmailScanRequest, UrlScanRequest
from engine import parser, rules, scorer

class TestRawScanAndApi(unittest.TestCase):

    def test_parse_raw_bytes_genuine_email(self):
        """Test parse_raw_bytes with genuine SPF/DKIM/DMARC headers."""
        raw_rfc5322 = (
            b"From: Security Team <security@bank.com>\r\n"
            b"Reply-To: security@bank.com\r\n"
            b"To: user@example.com\r\n"
            b"Subject: Security Alert: Account Verification\r\n"
            b"Date: Sat, 27 Sep 2026 12:00:00 +0000\r\n"
            b"Authentication-Results: mx.google.com; spf=pass (google.com: domain of security@bank.com designates 192.0.2.1 as permitted sender); dkim=pass header.i=@bank.com; dmarc=pass (p=REJECT) header.from=bank.com\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Please visit https://bank.com/portal to check your security settings.\r\n"
        )
        parsed = parser.parse_raw_bytes(raw_rfc5322)
        self.assertEqual(parsed["from"], "Security Team <security@bank.com>")
        self.assertEqual(parsed["from_domain"], "bank.com")
        self.assertEqual(parsed["display_name"], "Security Team")
        self.assertIn("spf=pass", parsed["auth_results"])
        self.assertIn("dkim=pass", parsed["auth_results"])
        self.assertIn("dmarc=pass", parsed["auth_results"])
        self.assertIn("https://bank.com/portal", parsed["urls"])

        # Test rules on this parsed email
        spf_check = rules.check_spf(parsed)
        dkim_check = rules.check_dkim(parsed)
        dmarc_check = rules.check_dmarc(parsed)

        self.assertEqual(spf_check["result"], "pass")
        self.assertEqual(spf_check["weight"], 0)
        self.assertIn("passed successfully", spf_check["explanation"])

        self.assertEqual(dkim_check["result"], "pass")
        self.assertEqual(dkim_check["weight"], 0)
        self.assertIn("verified successfully", dkim_check["explanation"])

        self.assertEqual(dmarc_check["result"], "pass")
        self.assertEqual(dmarc_check["weight"], 0)
        self.assertIn("passed successfully", dmarc_check["explanation"])

    def test_parse_raw_bytes_spoofed_auth_fail(self):
        """Test parse_raw_bytes with explicit SPF and DKIM fail headers."""
        raw_rfc5322 = (
            b"From: PayPal Support <service@paypal.com>\r\n"
            b"Reply-To: attacker@evil-phish.com\r\n"
            b"To: victim@example.com\r\n"
            b"Subject: Urgent: Account Suspended Immediately\r\n"
            b"Authentication-Results: mx.google.com; spf=fail (google.com: domain of service@paypal.com does not designate 198.51.100.1 as permitted sender); dkim=fail (bad signature) header.i=@paypal.com; dmarc=fail (p=REJECT) header.from=paypal.com\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"\r\n"
            b"<html><body>Dear customer, your account will be suspended. <a href='http://bit.ly/fake-login'>Verify your password</a></body></html>\r\n"
        )
        parsed = parser.parse_raw_bytes(raw_rfc5322)
        score_result = scorer.score_email(parsed)

        self.assertEqual(score_result["classification"], "Phishing")
        self.assertEqual(score_result["risk_level"], "CRITICAL")
        self.assertGreater(score_result["category_scores"]["Authentication"], 0)

        # Confirm SPF, DKIM, DMARC failed with weights
        flagged_checks = [f["check"] for f in score_result["flagged"]]
        self.assertIn("SPF Authentication", flagged_checks)
        self.assertIn("DKIM Signature", flagged_checks)
        self.assertIn("DMARC Alignment", flagged_checks)

    def test_api_scan_raw_endpoint_success(self):
        """Test POST /scan-raw endpoint handler with valid base64url email."""
        raw_rfc5322 = (
            b"From: Google Security <no-reply@accounts.google.com>\r\n"
            b"To: user@gmail.com\r\n"
            b"Subject: Security alert for your linked Google Account\r\n"
            b"Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\r\n"
            b"\r\n"
            b"Sign in attempt was blocked. Review activity at https://myaccount.google.com/notifications\r\n"
        )
        b64_raw = base64.urlsafe_b64encode(raw_rfc5322).decode('utf-8').rstrip('=')

        req = RawEmailScanRequest(raw=b64_raw)
        data = scan_raw_email(req)

        self.assertIn("risk", data)
        self.assertIn("status", data)
        self.assertIn("score", data)
        self.assertIn("reasons", data)
        self.assertIn("explanation", data)
        self.assertIn("meta", data)
        self.assertTrue(data["meta"]["auth_headers_available"])
        self.assertEqual(data["meta"]["scan_mode"], "Gmail API RFC 5322 Raw Scan")

    def test_api_scan_raw_endpoint_invalid_payload(self):
        """Test POST /scan-raw with empty or invalid payload raises 400 error."""
        with self.assertRaises(HTTPException) as ctx_empty:
            scan_raw_email(RawEmailScanRequest(raw=""))
        self.assertEqual(ctx_empty.exception.status_code, 400)

        with self.assertRaises(HTTPException) as ctx_bad:
            scan_raw_email(RawEmailScanRequest(raw="!!!not-valid-base64!!!"))
        self.assertEqual(ctx_bad.exception.status_code, 400)

    def test_api_scan_email_endpoint_unchanged(self):
        """Confirm /scan-email (DOM fallback path) works completely unchanged."""
        req = EmailScanRequest(
            sender="John Doe <john@company.com>",
            subject="Quarterly Review Meeting",
            body="Hi team, please find the quarterly presentation attached.",
            links=[{"text": "Company Portal", "href": "https://company.com/portal"}]
        )
        data = scan_email(req)
        self.assertIn("risk", data)
        self.assertIn("status", data)
        self.assertEqual(data["meta"]["scan_mode"], "Chrome Extension DOM Live Scan")
        self.assertFalse(data["meta"]["auth_headers_available"])

    def test_api_scan_url_endpoint_unchanged(self):
        """Confirm /scan-url (popup standalone checker) works completely unchanged."""
        # Safe URL
        data_safe = scan_url(UrlScanRequest(url="https://google.com"))
        self.assertEqual(data_safe["status"], "Safe")

        # Suspicious URL shortener
        data_short = scan_url(UrlScanRequest(url="https://bit.ly/3xY9z"))
        self.assertIn(data_short["status"], ["Suspicious", "Phishing"])

if __name__ == "__main__":
    unittest.main()
