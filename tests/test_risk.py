import unittest

from core.risk import (
    calculate_risk,
    get_risk_level,
)

class TestRisk(unittest.TestCase):

    def test_clean_approved_domain(self):
        score, level, reasons = calculate_risk(approved_match=True)

        self.assertEqual(score, 0)
        self.assertEqual(level, "LOW")
        self.assertEqual(reasons, [])

    def test_unapproved_domain(self):
        score, level, reasons = calculate_risk(approved_match=False)

        self.assertEqual(score, 10)
        self.assertEqual(level, "LOW")
        self.assertTrue(reasons)

    def test_historical_ioc_match(self):
        score, level, reasons = calculate_risk(
            approved_match=False,
            historical_ioc_match=True,
        )

        self.assertEqual(score, 60)
        self.assertEqual(level, "HIGH")

        self.assertIn(
            "Base domain appears in a historical IOC dataset.",
            reasons
        )

    def test_threatfox_live_match(self):
        threatfox_result = {
            "available": True,
            "matched": True,
            "results": [
                {
                    "confidence": 70,
                }
            ],
        }

        score, level, reasons = calculate_risk(
            approved_match=False,
            threatfox_result=threatfox_result,
        )

        self.assertEqual(score, 60)
        self.assertEqual(level, "HIGH")

        self.assertIn(
            "ThreatFox currently returns the base domain "
            "as a threat-intelligence IOC.",
            reasons
        )

    def test_threatfox_no_match(self):
        threatfox_result = {
            "available": True,
            "matched": False,
            "results": [],
        }

        score, level, reasons = calculate_risk(
            approved_match=False,
            threatfox_result=threatfox_result,
        )

        self.assertEqual(score, 10)
        self.assertEqual(level, "LOW")

    def test_similar_domain_with_digit(self):
        score, level, reasons = calculate_risk(
            approved_match=False,
            similar_match=True,
            base_digits=["0"],
        )

        self.assertEqual(score, 50)
        self.assertEqual(level, "HIGH")

    def test_approved_domain_with_subdomain_indicators(self):
        score, level, reasons = calculate_risk(
            approved_match=True,
            subdomain_digits=["3", "6", "5"],
            subdomain_special_characters=["-"],
        )

        self.assertEqual(score, 10)
        self.assertEqual(level, "LOW")
        self.assertTrue(reasons)

    def test_unicode_homoglyph_domain(self):
        score, level, reasons = calculate_risk(
            approved_match=False,
            non_ascii_characters=["\u043e"],
            homoglyphs=[("\u043e", "o", "U+043E", "CYRILLIC SMALL LETTER O")],
            mixed_script_labels=["micr\u043esoft"],
        )

        self.assertEqual(score, 65)
        self.assertEqual(level, "HIGH")

    def test_score_capped_at_100(self):
        score, level, reasons = calculate_risk(
            approved_match=False,
            similar_match=True,
            base_digits=["0"],
            base_special_characters=["-"],
            subdomain_digits=["3"],
            subdomain_special_characters=["-"],
            non_ascii_characters=["\u043e"],
            homoglyphs=[("\u043e", "o", "U+043E", "CYRILLIC SMALL LETTER O")],
            mixed_script_labels=["micr\u043esoft"],
            punycode_detected=True,
        )

        self.assertEqual(score, 100)
        self.assertEqual(level, "CRITICAL")

    def test_virustotal_one_malicious_vendor(self):
        virustotal_result = {
            "available": True,
            "matched": True,
            "query_status": "ok",
            "lookup_type": "domain",
            "stats": {
                "malicious": 1,
                "suspicious": 0,
                "harmless": 60,
                "undetected": 10,
                "timeout": 0,
            },
            "phishing_vendors": [],
        }

        score, level, reasons = calculate_risk(
            approved_match=True,
            virustotal_result=virustotal_result,
        )

        self.assertEqual(score, 5)
        self.assertEqual(level, "LOW")

    def test_virustotal_medium_vendor_consensus(self):
        virustotal_result = {
            "available": True,
            "matched": True,
            "query_status": "ok",
            "lookup_type": "domain",
            "stats": {
                "malicious": 4,
                "suspicious": 0,
                "harmless": 50,
                "undetected": 10,
                "timeout": 0,
            },
            "phishing_vendors": [],
        }

        score, level, reasons = calculate_risk(
            approved_match=True,
            virustotal_result=virustotal_result,
        )

        self.assertEqual(score, 10)

    def test_virustotal_high_vendor_consensus(self):
        virustotal_result = {
            "available": True,
            "matched": True,
            "query_status": "ok",
            "lookup_type": "domain",
            "stats": {
                "malicious": 12,
                "suspicious": 0,
                "harmless": 40,
                "undetected": 10,
                "timeout": 0,
            },
            "phishing_vendors": [],
        }

        score, level, reasons = calculate_risk(
            approved_match=True,
            virustotal_result=virustotal_result,
        )

        self.assertEqual(score, 30)
        self.assertEqual(level, "MODERATE")

    def test_virustotal_phishing_consensus_bonus(self):
        virustotal_result = {
            "available": True,
            "matched": True,
            "query_status": "ok",
            "lookup_type": "domain",
            "stats": {
                "malicious": 3,
                "suspicious": 0,
                "harmless": 50,
                "undetected": 10,
                "timeout": 0,
            },
            "phishing_vendors": [
                "Vendor A",
                "Vendor B",
            ],
        }

        score, level, reasons = calculate_risk(
            approved_match=True,
            virustotal_result=virustotal_result,
        )

        self.assertEqual(score, 20)

    def test_virustotal_no_findings_adds_no_risk(self):
        virustotal_result = {
            "available": True,
            "matched": False,
            "query_status": "ok",
            "lookup_type": "domain",
            "stats": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 65,
                "undetected": 5,
                "timeout": 0,
            },
            "phishing_vendors": [],
        }

        score, level, reasons = calculate_risk(
            approved_match=True,
            virustotal_result=virustotal_result,
        )

        self.assertEqual(score, 0)

    def test_urlhaus_online_url_match(self):
        urlhaus_result = {
            "available": True,
            "matched": True,
            "query_status": "ok",
            "lookup_type": "url",
            "details": {
                "url_status": "online",
            },
        }

        score, level, reasons = calculate_risk(
            approved_match=True,
            urlhaus_result=urlhaus_result,
        )

        self.assertEqual(score, 40)
        self.assertEqual(level, "MODERATE")

    def test_urlhaus_offline_url_match(self):
        urlhaus_result = {
            "available": True,
            "matched": True,
            "query_status": "ok",
            "lookup_type": "url",
            "details": {
                "url_status": "offline",
            },
        }

        score, level, reasons = calculate_risk(
            approved_match=True,
            urlhaus_result=urlhaus_result,
        )

        self.assertEqual(score, 25)
        self.assertEqual(level, "MODERATE")

    def test_urlhaus_host_with_active_urls(self):
        urlhaus_result = {
            "available": True,
            "matched": True,
            "query_status": "ok",
            "lookup_type": "domain",
            "details": {
                "url_count": 8,
                "online_url_count": 2,
            },
        }

        score, level, reasons = calculate_risk(
            approved_match=True,
            urlhaus_result=urlhaus_result,
        )

        self.assertEqual(score, 25)

    def test_urlhaus_host_with_historical_urls(self):
        urlhaus_result = {
            "available": True,
            "matched": True,
            "query_status": "ok",
            "lookup_type": "domain",
            "details": {
                "url_count": 8,
                "online_url_count": 0,
            },
        }

        score, level, reasons = calculate_risk(
            approved_match=True,
            urlhaus_result=urlhaus_result,
        )

        self.assertEqual(score, 10)

    def test_external_intel_not_found_adds_no_risk(self):
        virustotal_result = {
            "available": True,
            "matched": False,
            "query_status": "not_found",
            "lookup_type": "domain",
        }

        urlhaus_result = {
            "available": True,
            "matched": False,
            "query_status": "no_results",
            "lookup_type": "domain",
        }

        score, level, reasons = calculate_risk(
            approved_match=True,
            virustotal_result=virustotal_result,
            urlhaus_result=urlhaus_result,
        )

        self.assertEqual(score, 0)
        self.assertEqual(level, "LOW")

    def test_virustotal_and_urlhaus_scores_combine(self):
        virustotal_result = {
            "available": True,
            "matched": True,
            "query_status": "ok",
            "lookup_type": "url",
            "stats": {
                "malicious": 6,
                "suspicious": 0,
                "harmless": 30,
                "undetected": 10,
                "timeout": 0,
            },
            "phishing_vendors": [],
        }

        urlhaus_result = {
            "available": True,
            "matched": True,
            "query_status": "ok",
            "lookup_type": "url",
            "details": {
                "url_status": "online",
            },
        }

        score, level, reasons = calculate_risk(
            approved_match=False,
            virustotal_result=virustotal_result,
            urlhaus_result=urlhaus_result,
        )

        self.assertEqual(score, 70)
        self.assertEqual(level, "HIGH")

    def test_local_list_match_counts_when_live_not_checked(self):
        local_result = {
            "available": True,
            "matched": True,
            "freshness": "fresh",
            "matches": [{"matched_on": "base_domain"}],
        }

        threatfox_result = {
            "available": False,
            "matched": False,
            "query_status": "privacy_mode",
        }

        score, level, reasons = calculate_risk(
            approved_match=True,
            threatfox_result=threatfox_result,
            local_intel_result=local_result,
        )

        self.assertEqual(score, 40)
        self.assertEqual(level, "MODERATE")

    def test_stale_local_list_match_counts_less(self):
        local_result = {
            "available": True,
            "matched": True,
            "freshness": "stale",
            "matches": [{"matched_on": "base_domain"}],
        }

        score, level, reasons = calculate_risk(
            approved_match=True,
            local_intel_result=local_result,
        )

        self.assertEqual(score, 30)

    def test_local_list_not_counted_twice_with_live_threatfox(self):
        local_result = {
            "available": True,
            "matched": True,
            "freshness": "fresh",
            "matches": [{"matched_on": "base_domain"}],
        }

        threatfox_result = {
            "available": True,
            "matched": True,
            "results": [{"confidence": 50}],
        }

        score, level, reasons = calculate_risk(
            approved_match=True,
            threatfox_result=threatfox_result,
            local_intel_result=local_result,
        )

        # 45 for the live match and 5 for its confidence only.
        self.assertEqual(score, 50)

    def test_live_threatfox_wins_for_base_domain(self):
        local_result = {
            "available": True,
            "matched": True,
            "freshness": "fresh",
            "matches": [{"matched_on": "base_domain"}],
        }

        threatfox_result = {
            "available": True,
            "matched": False,
            "query_status": "no_result",
        }

        score, level, reasons = calculate_risk(
            approved_match=True,
            threatfox_result=threatfox_result,
            local_intel_result=local_result,
        )

        self.assertEqual(score, 0)

    def test_local_subdomain_or_url_match_still_counts(self):
        local_result = {
            "available": True,
            "matched": True,
            "freshness": "fresh",
            "matches": [{"matched_on": "url"}],
        }

        threatfox_result = {
            "available": True,
            "matched": False,
            "query_status": "no_result",
        }

        score, level, reasons = calculate_risk(
            approved_match=True,
            threatfox_result=threatfox_result,
            local_intel_result=local_result,
        )

        self.assertEqual(score, 40)

    def test_unavailable_local_list_adds_no_risk(self):
        local_result = {
            "available": False,
            "matched": False,
            "query_status": "expired",
            "matches": [],
        }

        score, level, reasons = calculate_risk(
            approved_match=True,
            local_intel_result=local_result,
        )

        self.assertEqual(score, 0)

if __name__ == "__main__":
    unittest.main()