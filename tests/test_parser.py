import unittest

from core.parser import validate_email, validate_domain


class TestParser(unittest.TestCase):

    def test_valid_email(self):
        self.assertTrue(validate_email("john@example.com"))

    def test_email_with_two_at_symbols(self):
        self.assertFalse(validate_email("john@@example.com"))

    def test_valid_domain(self):
        self.assertTrue(validate_domain("example.com"))

    def test_domain_without_tld(self):
        self.assertFalse(validate_domain("example"))

    def test_domain_with_empty_label(self):
        self.assertFalse(validate_domain("example..com"))

    def test_email_with_consecutive_dots(self):
        self.assertFalse(validate_email("john..doe@example.com")) 


if __name__ == "__main__":
    unittest.main()