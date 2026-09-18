import unittest

from core.domain_checker import (
    load_approved_domains,
    is_approved_domain,
)

class TestDomainChecker(unittest.TestCase):

    def test_load_approved_domains(self):
        approved_domains = load_approved_domains()

        self.assertIn("example.com", approved_domains)

    def test_approved_domain(self):
        approved_domains = {
            "example.com",
            "microsoft.com",
        }

        self.assertTrue(
            is_approved_domain("microsoft.com", approved_domains)
        )

    def test_unapproved_domain(self):
        approved_domains = {
            "example.com",
            "microsoft.com",
        }

        self.assertFalse(
            is_approved_domain("micros0ft.com", approved_domains)
        )

    def test_approved_email_domain(self):
        approved_domains = {
            "example.com",
            "microsoft.com",
        }

        self.assertTrue(
            is_approved_domain("microsoft.com", approved_domains)
        )


    def test_spoofed_email_domain(self):
        approved_domains = {
            "example.com",
            "microsoft.com",
        }

        self.assertFalse(
            is_approved_domain("micros0ft.com", approved_domains)
        )

        if __name__ == "__main__":
            unittest.main()