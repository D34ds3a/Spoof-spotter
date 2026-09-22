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

if __name__ == "__main__":
    unittest.main()