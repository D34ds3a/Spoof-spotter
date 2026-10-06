import unittest

from core.parser import (
    parse_domain,
    validate_email,
    validate_domain,
    extract_domain_parts,
)


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

    def test_email_starting_with_dot(self):
        self.assertFalse(validate_email(".john@example.com"))

    def test_email_ending_with_dot(self):
        self.assertFalse(validate_email("john.@example.com"))

    def test_domain_parts_without_subdomain(self):
        subdomain, base_domain = extract_domain_parts("example.com")

        self.assertEqual(subdomain, "")
        self.assertEqual(base_domain, "example.com")

    def test_domain_parts_with_subdomain(self):
        subdomain, base_domain = extract_domain_parts(
            "https://login.accounts.example.com/reset"
    )

        self.assertEqual(subdomain, "login.accounts")
        self.assertEqual(base_domain, "example.com")

    def test_domain_with_multi_level_suffix(self):
        subdomain, base_domain = extract_domain_parts(
            "https://store.example.co.uk"
    )

        self.assertEqual(subdomain, "store")
        self.assertEqual(base_domain, "example.co.uk")


    def test_bracketed_host_does_not_crash(self):
        self.assertEqual(parse_domain("http://[1.2.3.4]/"), "")
        self.assertEqual(parse_domain("http://[::1"), "")
        self.assertFalse(validate_domain("http://[1.2.3.4]/"))

    def test_email_domain_must_be_a_plain_hostname(self):
        self.assertFalse(validate_email("alice@example.net?x=1"))
        self.assertFalse(validate_email("alice@example.net:8080"))
        self.assertFalse(validate_email("alice@example.net#x"))
        self.assertFalse(validate_email("alice@[1.2.3.4]"))
        self.assertTrue(validate_email("Alice@Example.net"))

    def test_extract_domain_parts_works_offline(self):
        self.assertEqual(
            extract_domain_parts("login.example.co.uk"),
            ("login", "example.co.uk"),
        )


if __name__ == "__main__":
    unittest.main()