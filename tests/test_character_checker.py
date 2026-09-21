import unittest

from core.character_checker import (
    find_digits,
    find_special_characters,
    has_digits,
    has_special_characters,
)

from core.character_checker import (
    find_digits,
    find_special_characters,
    has_digits,
    has_special_characters,
    find_non_ascii_characters,
    find_homoglyphs,
    find_mixed_script_labels,
    has_punycode,
    decode_punycode_domain,
)

class TestCharacterChecker(unittest.TestCase):

    def test_domain_without_digits(self):
        self.assertFalse(has_digits("microsoft.com"))

    def test_domain_with_digit(self):
        self.assertTrue(has_digits("micros0ft.com"))

    def test_find_multiple_digits(self):
        digits = find_digits("office365.com")

        self.assertEqual(
            digits,
            ["3", "6", "5"]

        )

    def test_domain_without_special_characters(self):
        self.assertFalse(has_special_characters("example.com"))

    def test_domain_with_hyphen(self):
        self.assertTrue(has_special_characters("my-bank.com"))

    def test_find_special_character(self):
        characters = find_special_characters("my-bank.com" )

        self.assertEqual(
            characters,
            ["-"]
        )

    def test_subdomain_with_digits(self):
        digits = find_digits("secure-login365")

        self.assertEqual(
            digits,
            ["3", "6", "5"]
        )
        
    def test_subdomain_with_hyphen(self):
        characters = find_special_characters("secure-login365")

        self.assertEqual(
            characters,
            ["-"]
        )

    def test_ascii_domain_has_no_unicode(self):
        characters = find_non_ascii_characters("microsoft.com")

        self.assertEqual(characters, [])

    def test_cyrillic_o_detected(self):
        domain = "micr\u043esoft.com"

        characters = find_non_ascii_characters(domain)

        self.assertIn("\u043e", characters)

    def test_homoglyph_detected(self):
        domain = "micr\u043esoft.com"

        findings = find_homoglyphs(domain)

        self.assertTrue(findings)

    def test_mixed_script_label_detected(self):
        domain = "micr\u043esoft.com"

        mixed_labels = find_mixed_script_labels(domain)

        self.assertEqual(
            mixed_labels,
            ["micr\u043esoft"]
        )

    def test_punycode_detected(self):
        self.assertTrue(has_punycode("xn--bcher-kva.de"))

    def test_punycode_decoding(self):
        decoded = decode_punycode_domain("xn--bcher-kva.de")

        self.assertEqual(
            decoded,
            "bücher.de"
        )


if __name__ == "__main__":
    unittest.main()