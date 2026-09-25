import os
import unittest
from engine import parser, rules, scorer, reputation, explainer

SAMPLE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "sample_emails")

class TestEmailAnalyzerRules(unittest.TestCase):

    def test_parser_legit_college(self):
        filepath = os.path.join(SAMPLE_DIR, "legit_college_notice.eml")
        self.assertTrue(os.path.exists(filepath), "Sample file missing")
        parsed = parser.parse_eml(filepath)
        
        self.assertIn("stateuniv.edu", parsed["from_domain"])
        self.assertIn("Course Registration", parsed["subject"])
        self.assertTrue(len(parsed["urls"]) > 0)
        self.assertIn("https://stateuniv.edu/courses", parsed["urls"])

    def test_spf_rule(self):
        # Pass
        res_pass = rules.check_spf({"auth_results": "mx.google.com; spf=pass"})
        self.assertEqual(res_pass["result"], "pass")
        self.assertEqual(res_pass["weight"], 0)

        # Fail
        res_fail = rules.check_spf({"auth_results": "mx.google.com; spf=fail (IP not permitted)"})
        self.assertEqual(res_fail["result"], "fail")
        self.assertEqual(res_fail["weight"], 20)

        # None / Missing / DOM Scraped
        res_none = rules.check_spf({"auth_results": ""})
        self.assertEqual(res_none["result"], "none")
        self.assertEqual(res_none["weight"], 0)
        self.assertIn("unavailable", res_none["explanation"])

    def test_dkim_rule(self):
        # Fail
        res_fail = rules.check_dkim({"auth_results": "dkim=fail header.i=@test.com"})
        self.assertEqual(res_fail["result"], "fail")
        self.assertEqual(res_fail["weight"], 20)

        # Pass
        res_pass = rules.check_dkim({"auth_results": "dkim=pass header.i=@test.com"})
        self.assertEqual(res_pass["result"], "pass")
        self.assertEqual(res_pass["weight"], 0)

        # None / Missing / DOM Scraped
        res_none = rules.check_dkim({"auth_results": ""})
        self.assertEqual(res_none["result"], "none")
        self.assertEqual(res_none["weight"], 0)
        self.assertIn("unavailable", res_none["explanation"])

    def test_dmarc_rule(self):
        # Fail
        res_fail = rules.check_dmarc({"auth_results": "dmarc=fail (p=REJECT)"})
        self.assertEqual(res_fail["result"], "fail")
        self.assertEqual(res_fail["weight"], 15)

        # Pass
        res_pass = rules.check_dmarc({"auth_results": "dmarc=pass"})
        self.assertEqual(res_pass["result"], "pass")
        self.assertEqual(res_pass["weight"], 0)

        # None / Missing / DOM Scraped
        res_none = rules.check_dmarc({"auth_results": ""})
        self.assertEqual(res_none["result"], "none")
        self.assertEqual(res_none["weight"], 0)
        self.assertIn("unavailable", res_none["explanation"])

    def test_reply_to_mismatch(self):
        # Mismatch
        res = rules.check_reply_to_mismatch({
            "from_domain": "stateuniv.edu",
            "reply_to_domain": "hacker@evil.com"
        })
        self.assertEqual(res["result"], "fail")
        self.assertEqual(res["weight"], 15)

        # Match
        res2 = rules.check_reply_to_mismatch({
            "from_domain": "stateuniv.edu",
            "reply_to_domain": "stateuniv.edu"
        })
        self.assertEqual(res2["result"], "pass")
        self.assertEqual(res2["weight"], 0)

    def test_display_name_spoofing(self):
        # Impersonation
        res = rules.check_display_name({
            "display_name": "Campus IT Support",
            "from_domain": "random-scam.net"
        })
        self.assertEqual(res["result"], "fail")
        self.assertEqual(res["weight"], 10)

        # Legitimate
        res2 = rules.check_display_name({
            "display_name": "PayPal Support",
            "from_domain": "paypal.com"
        })
        self.assertEqual(res2["result"], "pass")
        self.assertEqual(res2["weight"], 0)

    def test_url_shorteners(self):
        res = rules.check_shorteners({"urls": ["http://bit.ly/malicious-link", "https://example.com"]})
        self.assertEqual(res["result"], "fail")
        self.assertEqual(res["weight"], 10)

    def test_ip_urls(self):
        res = rules.check_ip_urls({"urls": ["http://192.168.1.100/admin-login"], "body": ""})
        self.assertEqual(res["result"], "fail")
        self.assertEqual(res["weight"], 15)

    def test_href_mismatch(self):
        # Malicious domain mismatch
        res = rules.check_href_mismatch({
            "html_links": [{"text": "https://paypal.com/login", "href": "http://evil-phish.biz"}]
        })
        self.assertEqual(res["result"], "fail")
        self.assertEqual(res["weight"], 15)

        # Malicious shortener masquerading as college domain (must be flagged!)
        res_short = rules.check_href_mismatch({
            "html_links": [{"text": "https://college.edu/verify", "href": "http://bit.ly/xyz123"}]
        })
        self.assertEqual(res_short["result"], "fail")
        self.assertEqual(res_short["weight"], 15)

        # Legitimate ESP tracking redirect (SendGrid - NPTEL / IIT Madras use case)
        res_esp = rules.check_href_mismatch({
            "html_links": [{"text": "https://onlinecourses.nptel.ac.in/noc24_cs01", "href": "http://ct.sendgrid.net/ls/click?upn=xyz"}]
        })
        self.assertEqual(res_esp["result"], "pass")
        self.assertEqual(res_esp["weight"], 0)

        # Legitimate ESP tracking redirect (Mailchimp)
        res_mc = rules.check_href_mismatch({
            "html_links": [{"text": "https://company.com/newsletter", "href": "https://links.mailchimp.com/track/click?u=123"}]
        })
        self.assertEqual(res_mc["result"], "pass")
        self.assertEqual(res_mc["weight"], 0)

    def test_urgency_keywords(self):
        res = rules.check_urgency_keywords({
            "subject": "URGENT ACTION REQUIRED",
            "body": "Your account will be suspended immediately within 24 hours."
        })
        self.assertEqual(res["result"], "fail")
        self.assertTrue(res["weight"] >= 10)

    def test_generic_greeting(self):
        res = rules.check_generic_greeting({"body": "Dear Customer, please verify your credentials."})
        self.assertEqual(res["result"], "fail")
        self.assertEqual(res["weight"], 5)

    def test_credential_harvesting_rule(self):
        # Flagged
        res_flag = rules.check_credential_harvesting({
            "body": "Please confirm your login and verify your password immediately."
        })
        self.assertEqual(res_flag["result"], "flagged")
        self.assertEqual(res_flag["weight"], 15)
        self.assertIn("verify your password", res_flag["explanation"])

        # Pass
        res_pass = rules.check_credential_harvesting({
            "body": "Welcome to our newsletter on quantum computing breakthroughs."
        })
        self.assertEqual(res_pass["result"], "pass")
        self.assertEqual(res_pass["weight"], 0)

    def test_account_threat_language_rule(self):
        # Flagged
        res_flag = rules.check_account_threat_language({
            "subject": "Security Notice",
            "body": "Your account will be suspended within 24 hours."
        })
        self.assertEqual(res_flag["result"], "flagged")
        self.assertEqual(res_flag["weight"], 10)
        self.assertIn("account will be suspended", res_flag["explanation"])

        # Pass
        res_pass = rules.check_account_threat_language({
            "subject": "Course Catalog Published",
            "body": "Please review your course options and schedule worksheet."
        })
        self.assertEqual(res_pass["result"], "pass")
        self.assertEqual(res_pass["weight"], 0)

    def test_brand_impersonation_rule(self):
        # Flagged: Claims Gmail Security Team but sent from malicious external domain
        res_flag = rules.check_brand_impersonation({
            "from": "Gmail Security Team <support@gmail-update-security.biz>",
            "display_name": "Gmail Security Team",
            "from_domain": "gmail-update-security.biz"
        })
        self.assertEqual(res_flag["result"], "flagged")
        self.assertEqual(res_flag["weight"], 10)
        self.assertIn("Gmail", res_flag["explanation"])

        # Pass: Legitimate PayPal
        res_pass = rules.check_brand_impersonation({
            "from": "PayPal Service <service@paypal.com>",
            "display_name": "PayPal Service",
            "from_domain": "paypal.com"
        })
        self.assertEqual(res_pass["result"], "pass")
        self.assertEqual(res_pass["weight"], 0)

    def test_false_positive_safeguard(self):
        # Legitimate bank reset email with threat/credential language, but valid SPF/DKIM and no domain mismatch
        legit_reset = {
            "from": "support@stateuniv.edu",
            "from_domain": "stateuniv.edu",
            "display_name": "State University Support",
            "subject": "Action Required: Verify your identity to update credentials",
            "body": "Dear User, Please verify your password. If not done, account access will be restricted.",
            "auth_results": "mx.google.com; spf=pass; dkim=pass; dmarc=pass",
            "urls": ["https://stateuniv.edu/login"]
        }
        scored = scorer.score_email(legit_reset)
        # Even if score reaches threshold, without corroborating signals it must NOT classify as Phishing
        self.assertNotEqual(scored["classification"], "Phishing")

    def test_lookalike_detection(self):
        allowlist = {"stateuniv.edu", "microsoft.com", "paypal.com"}
        res = reputation.check_lookalike_reputation("stateunlv.edu", allowlist)
        self.assertEqual(res["result"], "fail")
        self.assertEqual(res["weight"], 20)

    def test_all_sample_emails_scoring(self):
        """Verify that all 6 sample emails classify accurately according to requirements."""
        samples = [
            ("legit_college_notice.eml", "Safe"),
            ("legit_newsletter.eml", "Safe"),
            ("phish_domain_spoof.eml", "Phishing"),
            ("phish_urgent_creds.eml", "Phishing"),
            ("phish_spf_fail.eml", "Phishing"),
            ("phish_url_shortener.eml", "Phishing"),
        ]

        for filename, expected_class in samples:
            path = os.path.join(SAMPLE_DIR, filename)
            self.assertTrue(os.path.exists(path), f"Missing {filename}")
            parsed = parser.parse_eml(path)
            scored = scorer.score_email(parsed)

            if expected_class == "Safe":
                self.assertLess(scored["score"], 20, f"{filename} should score < 20 (got {scored['score']})")
                self.assertEqual(scored["classification"], "Safe", f"{filename} should be Safe")
            else:
                self.assertGreaterEqual(scored["score"], 50, f"{filename} should score >= 50 (got {scored['score']})")
                self.assertEqual(scored["classification"], "Phishing", f"{filename} should be Phishing")

    def test_fallback_explainer(self):
        flagged = [{"check": "SPF", "explanation": "Failed SPF check", "weight": 20}]
        exp = explainer.fallback_explanation(flagged, "Phishing")
        self.assertIn("summary", exp)
        self.assertIn("recommendation", exp)
        self.assertIn("Failed SPF check", exp["summary"])

    def test_malformed_input(self):
        # Empty string or bytes should not crash
        parsed = parser.parse_eml(b"From: test@example.com\nSubject: Test\n\nEmpty body")
        scored = scorer.score_email(parsed)
        self.assertIn("score", scored)

if __name__ == "__main__":
    unittest.main()
