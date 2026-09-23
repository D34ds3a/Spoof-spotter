import unittest

from core.report import generate_report

class TestReport(unittest.TestCase):

    def test_clean_domain_report(self):
        data = {
            "original_input": "microsoft.com",
            "input_type": "DOMAIN/WEBSITE",
            "email_address": None,
            "hostname": "microsoft.com",
            "subdomain": "",
            "base_domain": "microsoft.com",
            "approved_match": True,
            "closest_domain": "microsoft.com",
            "similarity_score": 1.0,
            "similar_match": True,
            "base_digits": [],
            "base_special_characters": [],
            "subdomain_digits": [],
            "subdomain_special_characters": [],
            "punycode_detected": False,
            "decoded_domain": "microsoft.com",
            "unicode_characters": [],
            "homoglyphs": [],
            "mixed_script_labels": [],
            "risk_score": 0,
            "risk_level": "LOW",
            "risk_reasons": [],
        }

        report = generate_report(data)

        self.assertIn("Original input: microsoft.com", report)

        self.assertIn("Risk score: 0/100",report)

        self.assertIn("Indicators: None",report)