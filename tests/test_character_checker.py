import unittest

from core.character_checker import (
    find_digits,
    find_special_characters,
    has_digits,
    has_special_characters,
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


if __name__ == "__main__":
    unittest.main()