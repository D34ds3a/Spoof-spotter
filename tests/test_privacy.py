import unittest

from core.privacy import (
    PRIVACY_MODE,
    STANDARD_MODE,
    allow_external_lookup,
    get_mode_policy,
    is_internal_hostname,
    is_ip_address,
    is_private_or_reserved_ip,
    normalize_mode,
    service_allowed,
)


class TestPrivacy(unittest.TestCase):

    def test_detects_ip_address(self):
        self.assertTrue(is_ip_address("192.168.1.10"))

    def test_domain_is_not_ip_address(self):
        self.assertFalse(is_ip_address("example.com"))

    def test_private_ip_is_blocked(self):
        self.assertTrue(is_private_or_reserved_ip("192.168.1.10"))

    def test_loopback_ip_is_blocked(self):
        self.assertTrue(is_private_or_reserved_ip("127.0.0.1"))

    def test_internal_hostname_detected(self):
        self.assertTrue(is_internal_hostname("server01"))

    def test_localhost_detected(self):
        self.assertTrue(is_internal_hostname("localhost"))

    def test_public_domain_allowed(self):
        self.assertTrue(allow_external_lookup("example.com"))

    def test_private_ip_external_lookup_blocked(self):
        self.assertFalse(allow_external_lookup("10.0.0.15"))

    def test_internal_hostname_external_lookup_blocked(self):
        self.assertFalse(allow_external_lookup("payroll"))

    def test_standard_mode_normalized(self):
        self.assertEqual(
            normalize_mode("STANDARD"),
            STANDARD_MODE,
        )


    def test_privacy_mode_normalized(self):
        self.assertEqual(
            normalize_mode(" Privacy "),
            PRIVACY_MODE,
    )


    def test_unknown_mode_falls_back_to_standard(self):
        self.assertEqual(
            normalize_mode("banana"),
            STANDARD_MODE,
        )


    def test_local_intelligence_allowed_in_standard_mode(self):
        self.assertTrue(
            service_allowed(
                "local",
                STANDARD_MODE,
            )
        )


    def test_local_intelligence_allowed_in_privacy_mode(self):
        self.assertTrue(
            service_allowed(
                "local",
                PRIVACY_MODE,
            )
        )


    def test_google_allowed_in_standard_mode(self):
        self.assertTrue(
            service_allowed(
                "google_safe_browsing",
                STANDARD_MODE,
            )
        )


    def test_google_allowed_in_privacy_mode(self):
        self.assertTrue(
            service_allowed(
                "google_safe_browsing",
                PRIVACY_MODE,
            )
        )


    def test_threatfox_allowed_in_standard_mode(self):
        self.assertTrue(
            service_allowed(
                "threatfox",
                STANDARD_MODE,
            )
        )


    def test_threatfox_blocked_in_privacy_mode(self):
        self.assertFalse(
            service_allowed(
                "threatfox",
                PRIVACY_MODE,
            )
        )


    def test_virustotal_allowed_in_standard_mode(self):
        self.assertTrue(
            service_allowed(
                "virustotal",
                STANDARD_MODE,
            )
        )


    def test_virustotal_blocked_in_privacy_mode(self):
        self.assertFalse(
            service_allowed(
                "virustotal",
                PRIVACY_MODE,
            )
        )


    def test_urlhaus_allowed_in_standard_mode(self):
        self.assertTrue(
            service_allowed(
                "urlhaus",
                STANDARD_MODE,
            )
        )


    def test_urlhaus_blocked_in_privacy_mode(self):
        self.assertFalse(
            service_allowed(
                "urlhaus",
                PRIVACY_MODE,
            )
        )


    def test_unknown_service_blocked(self):
        self.assertFalse(
            service_allowed(
                "not_a_real_service",
                STANDARD_MODE,
            )
        )


    def test_privacy_safe_phishing_allowed_in_privacy_mode(self):
        self.assertTrue(
            service_allowed(
                "privacy_safe_phishing",
                PRIVACY_MODE,
            )
         )


    def test_standard_policy_has_live_services(self):
        policy = get_mode_policy(STANDARD_MODE)

        self.assertTrue(policy["threatfox_live"])
        self.assertTrue(policy["google_safe_browsing"])
        self.assertTrue(policy["live_phishing"])
        self.assertTrue(policy["urlhaus_live"])


    def test_privacy_policy_blocks_cleartext_services(self):
        policy = get_mode_policy(PRIVACY_MODE)

        self.assertFalse(policy["threatfox_live"])
        self.assertFalse(policy["live_phishing"])
        self.assertFalse(policy["urlhaus_live"])
        self.assertTrue(policy["google_safe_browsing"])
        self.assertTrue(policy["privacy_safe_phishing"])

    def test_public_ipv4_external_lookup_blocked(self):
        self.assertFalse(allow_external_lookup("8.8.8.8"))

    def test_public_ipv6_external_lookup_blocked(self):
        self.assertFalse(allow_external_lookup("2001:4860:4860::8888"))


if __name__ == "__main__":
    unittest.main()