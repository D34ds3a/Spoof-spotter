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
            "closest_reference_domain": "microsoft.com",
            "similarity_score": 1.0,
            "similar_match": False,
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
            "closest_reference_domain": "microsoft.com",
            "similarity_score": 1.0,
            "similar_match": False,
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
            "closest_reference_domain": "example.com",
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

    def base_data(self, **overrides):
        data = {
            "original_input":
                "https://example.com/login",
            "input_type": "DOMAIN/WEBSITE",
            "analysis_mode": "standard",
            "email_address": None,
            "hostname": "example.com",
            "subdomain": "",
            "base_domain": "example.com",

            "approved_match": False,
            "closest_reference_domain":
                "example.com",
            "similarity_score": 1.0,
            "similar_match": False,

            "historical_ioc_match": False,
            "historical_ioc_sources": [],
            "historical_ioc_details": [],

            "base_digits": [],
            "base_special_characters": [],
            "subdomain_digits": [],
            "subdomain_special_characters": [],

            "punycode_detected": False,
            "decoded_domain":
                "example.com",
            "unicode_characters": [],
            "homoglyphs": [],
            "mixed_script_labels": [],

            "risk_score": 10,
            "risk_level": "LOW",
            "risk_reasons": [
                "Base domain does not "
                "match an approved domain."
            ],
        }

        data.update(overrides)

        return data

    def test_privacy_mode_blocks_virustotal_and_urlhaus(
        self
    ):
        data = self.base_data(
            analysis_mode="privacy",
            virustotal_result={
                "available": False,
                "matched": False,
                "source": "VirusTotal",
                "query_status": "privacy_mode",
                "lookup_type": None,
            },
            urlhaus_result={
                "available": False,
                "matched": False,
                "source": "URLhaus",
                "query_status": "privacy_mode",
                "lookup_type": None,
            },
        )

        report = generate_report(data)

        self.assertIn(
            "VirusTotal status: Privacy Mode",
            report,
        )

        self.assertIn(
            "VirusTotal flagged: Not checked",
            report,
        )

        self.assertIn(
            "URLhaus status: Privacy Mode",
            report,
        )

        self.assertIn(
            "sent to VirusTotal.",
            report,
        )

        self.assertIn(
            "sent to URLhaus.",
            report,
        )

    def test_virustotal_phishing_verdict_report(
        self
    ):
        data = self.base_data(
            virustotal_result={
                "available": True,
                "matched": True,
                "source": "VirusTotal",
                "query_status": "ok",
                "lookup_type": "url",
                "stats": {
                    "malicious": 7,
                    "suspicious": 1,
                    "harmless": 60,
                    "undetected": 25,
                    "timeout": 0,
                },
                "engines_total": 93,
                "phishing_vendors": [
                    "Vendor A",
                    "Vendor B",
                    "Vendor C",
                    "Vendor D",
                    "Vendor E",
                    "Vendor F",
                    "Vendor G",
                ],
                "reputation": -15,
                "last_analysis_date":
                    "2026-09-30 12:00 UTC",
                "report_link":
                    "https://www.virustotal.com/gui/url/abc",
            },
        )

        report = generate_report(data)

        self.assertIn(
            "VirusTotal flagged: Yes",
            report,
        )

        self.assertIn(
            "Lookup type: Full URL",
            report,
        )

        self.assertIn(
            "Security vendors: 7 malicious, "
            "1 suspicious, 60 harmless, "
            "25 undetected (of 93)",
            report,
        )

        self.assertIn(
            "Vendors reporting phishing: "
            "Vendor A, Vendor B, Vendor C, "
            "Vendor D, Vendor E (+2 more)",
            report,
        )

        self.assertIn(
            "Community reputation: -15",
            report,
        )

    def test_virustotal_not_found_report(
        self
    ):
        data = self.base_data(
            virustotal_result={
                "available": True,
                "matched": False,
                "source": "VirusTotal",
                "query_status": "not_found",
                "lookup_type": "domain",
            },
        )

        report = generate_report(data)

        self.assertIn(
            "VirusTotal flagged: No",
            report,
        )

        self.assertIn(
            "Lookup type: Domain",
            report,
        )

        self.assertIn(
            "does not mean it is safe",
            report,
        )

    def test_urlhaus_host_match_report(
        self
    ):
        data = self.base_data(
            urlhaus_result={
                "available": True,
                "matched": True,
                "source": "URLhaus",
                "query_status": "ok",
                "lookup_type": "domain",
                "details": {
                    "url_count": 12,
                    "online_url_count": 3,
                    "first_seen":
                        "2026-09-01 10:00:00 UTC",
                    "threats": [
                        "malware_download"
                    ],
                    "tags": [
                        "exe",
                        "ClearFake",
                    ],
                    "reference":
                        "https://urlhaus.abuse.ch/host/example.com/",
                    "blocklists": [
                        "Spamhaus DBL (abused_legit_malware)"
                    ],
                },
            },
        )

        report = generate_report(data)

        self.assertIn(
            "URLhaus match: Yes",
            report,
        )

        self.assertIn(
            "Lookup type: Host",
            report,
        )

        self.assertIn(
            "Malware URLs recorded for host: "
            "12 (3 currently online)",
            report,
        )

        self.assertIn(
            "Threats: Malware Download",
            report,
        )

        self.assertIn(
            "Blocklists: Spamhaus DBL",
            report,
        )

    def test_urlhaus_missing_key_report(
        self
    ):
        data = self.base_data(
            urlhaus_result={
                "available": False,
                "matched": False,
                "source": "URLhaus",
                "query_status": "missing_auth_key",
                "lookup_type": "url",
            },
        )

        report = generate_report(data)

        self.assertIn(
            "URLhaus match: Not checked",
            report,
        )

        self.assertIn(
            "same abuse.ch Auth-Key as ThreatFox",
            report,
        )


if __name__ == "__main__":
    unittest.main()