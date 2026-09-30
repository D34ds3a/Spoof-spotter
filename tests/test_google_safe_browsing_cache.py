import unittest

from core.google_safe_browsing_cache import (
    SafeBrowsingCache,
)


class FakeClock:

    def __init__(self):
        self.value = 1000.0

    def __call__(self):
        return self.value

    def advance(
        self,
        seconds,
    ):
        self.value += seconds


class TestSafeBrowsingCache(
    unittest.TestCase
):

    def test_cache_returns_value_before_expiration(
        self,
    ):
        clock = FakeClock()

        cache = SafeBrowsingCache(
            clock=clock
        )

        cache.set(
            "AAAAAA==",
            [],
            300,
        )

        self.assertEqual(
            cache.get(
                "AAAAAA=="
            ),
            [],
        )

    def test_cache_expires_value(
        self,
    ):
        clock = FakeClock()

        cache = SafeBrowsingCache(
            clock=clock
        )

        cache.set(
            "AAAAAA==",
            [],
            300,
        )

        clock.advance(301)

        self.assertIsNone(
            cache.get(
                "AAAAAA=="
            )
        )

    def test_cache_exists_until_exact_expiration(
        self,
    ):
        clock = FakeClock()

        cache = SafeBrowsingCache(
            clock=clock
        )

        cache.set(
            "AAAAAA==",
            [],
            300,
        )

        clock.advance(299)

        self.assertEqual(
            cache.get(
                "AAAAAA=="
            ),
            [],
        )

    def test_zero_duration_not_cached(
        self,
    ):
        cache = SafeBrowsingCache()

        cache.set(
            "AAAAAA==",
            [],
            0,
        )

        self.assertIsNone(
            cache.get(
                "AAAAAA=="
            )
        )

    def test_negative_duration_not_cached(
        self,
    ):
        cache = SafeBrowsingCache()

        cache.set(
            "AAAAAA==",
            [],
            -10,
        )

        self.assertIsNone(
            cache.get(
                "AAAAAA=="
            )
        )

    def test_clear_removes_entries(self):
        cache = SafeBrowsingCache()

        cache.set(
            "AAAAAA==",
            [],
            300,
        )

        cache.clear()

        self.assertIsNone(
            cache.get(
                "AAAAAA=="
            )
        )


if __name__ == "__main__":
    unittest.main()