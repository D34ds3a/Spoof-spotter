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
            "historical_ioc_match": False,
            "historical_ioc_sources": [],
            "historical_ioc_details": [],
        }

        report = generate_report(data)
        
        self.assertIn("Original input: microsoft.com", report)
        
        self.assertIn("Risk score: 0/100", report)
        
        self.assertIn("Indicators: None", report)
        

    def test_report_hides_empty_subdomain_details(self):
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

            "historical_ioc_match": False,
            "historical_ioc_sources": [],
            "historical_ioc_details": [],
        }

        report = generate_report(data)

        self.assertIn("Subdomain: None", report)

        self.assertNotIn("Subdomain numbers detected:", report)

        self.assertNotIn(
            "Subdomain special characters detected:", report)

def test_historical_ioc_report_details(self):
    data = {
        "original_input": "bad-example.com",
        "input_type": "DOMAIN/WEBSITE",
        "email_address": None,
        "hostname": "bad-example.com",
        "subdomain": "",
        "base_domain": "bad-example.com",

        "approved_match": False,
        "closest_domain": "example.com",
        "similarity_score": 0.75,
        "similar_match": False,

        "base_digits": [],
        "base_special_characters": [],
        "subdomain_digits": [],
        "subdomain_special_characters": [],

        "punycode_detected": False,
        "decoded_domain": "bad-example.com",
        "unicode_characters": [],
        "homoglyphs": [],
        "mixed_script_labels": [],

        "risk_score": 30,
        "risk_level": "MODERATE",
        "risk_reasons": [
            "Base domain does not match an approved domain.",
            "Base domain appears in a historical IOC dataset.",
        ],

        "historical_ioc_match": True,
        "historical_ioc_sources": [
            "FBI LabHost FLASH"
        ],
        "historical_ioc_details": [
            {
                "source": "FBI LabHost FLASH",
                "creation_date": "11/9/2021",
                "status": "historical",
            }
        ],
    }

    report = generate_report(data)

    self.assertIn("Historical IOC match: Yes", report)

    self.assertIn("FBI LabHost FLASH", report)

    self.assertIn("11/9/2021", report)

       

       
if __name__ == "__main__":
    unittest.main()