import unittest

from core.similarity import (
    calculate_similarity,
    find_closest_domain,
    is_similar_score,
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
        reference_domains = {
            "google.com",
            "github.com",
            "microsoft.com",
        }

        closest_domain, score = find_closest_domain(
            "micros0ft.com",
            reference_domains
        )

        self.assertEqual(
            closest_domain,
            "microsoft.com"
        )

        self.assertGreater(score, 0.80)

    def test_similar_domain_detected(self):
        score = calculate_similarity(
            "micros0ft.com",
            "microsoft.com"
        )

        self.assertTrue(
            is_similar_score(score)
        )

    def test_unrelated_domain_not_similar(self):
        score = calculate_similarity(
            "totallydifferentwebsite.net",
            "microsoft.com"
        )

        self.assertFalse(
            is_similar_score(score)
        )

    def test_similarity_threshold(self):
        self.assertTrue(
            is_similar_score(0.80)
        )


if __name__ == "__main__":
    unittest.main()