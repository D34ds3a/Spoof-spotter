import unittest

from core.similarity import (
    calculate_similarity,
    find_closest_domain,
    is_similar_domain,
)


class TestSimilarity(unittest.TestCase):

    def test_identical_domains(self):
        score = calculate_similarity(
            "microsoft.com",
            "microsoft.com"
        )

        self.assertEqual(score, 1.0)

    def test_similar_domains(self):
        score = calculate_similarity(
            "micros0ft.com",
            "microsoft.com"
        )

        self.assertGreater(score, 0.80)

    def test_find_closest_domain(self):
        approved_domains = {
            "google.com",
            "github.com",
            "microsoft.com",
        }

        closest_domain, score = find_closest_domain(
            "micros0ft.com",
            approved_domains
        )

        self.assertEqual(
            closest_domain,
            "microsoft.com"
        )

        self.assertGreater(score, 0.80)

    def test_similar_domain_detected(self):
        approved_domains = {
            "google.com",
            "microsoft.com",
        }

        self.assertTrue(
            is_similar_domain(
                "micros0ft.com",
                approved_domains
            )
        )
    def test_unrelated_domain_not_similar(self):
        approved_domains = {
            "microsoft.com",
            "google.com",
        }

        self.assertFalse(
            is_similar_domain(
                "totallydifferentwebsite.net",
                approved_domains
            )
        )

if __name__ == "__main__":
    unittest.main()