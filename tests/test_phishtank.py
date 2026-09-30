import unittest

from unittest.mock import (
    Mock,
    patch,
)

import requests

from core.phishtank import (
    PHISHTANK_API_URL,
    PHISHTANK_USER_AGENT,
    check_url,
)


class TestPhishTank(
    unittest.TestCase
):

    def test_empty_url(self):
        result = check_url(
            ""
        )

        self.assertTrue(
            result["available"]
        )

        self.assertFalse(
            result["matched"]
        )

        self.assertEqual(
            result["query_status"],
            "empty_url",
        )

    @patch(
        "core.phishtank."
        "requests.post"
    )
    def test_confirmed_phish(
        self,
        mock_post,
    ):
        response = Mock()

        response.status_code = 200

        response.headers = {
            "X-Request-Limit": "100",
            "X-Request-Count": "1",
            "X-Request-Limit-Interval":
            "300 Seconds",
        }

        response.json.return_value = {
            "results": {
                "url": (
                    "https://bad.example/"
                ),
                "in_database": True,
                "phish_id": 12345,
                "phish_detail_page": (
                    "https://phishtank.test/"
                    "detail"
                ),
                "verified": "y",
                "verified_at": (
                    "2026-09-29T00:00:00"
                    "+00:00"
                ),
                "valid": "y",
                "submitted_at": (
                    "2026-09-28T23:00:00"
                    "+00:00"
                ),
            }
        }

        response.raise_for_status.return_value = (
            None
        )

        mock_post.return_value = (
            response
        )

        result = check_url(
            "https://bad.example/",
            api_key="fake-test-key",
        )

        self.assertTrue(
            result["available"]
        )

        self.assertTrue(
            result["listed"]
        )

        self.assertTrue(
            result["matched"]
        )

        self.assertEqual(
            result["query_status"],
            "ok",
        )

        self.assertEqual(
            result["result"][
                "phish_id"
            ],
            12345,
        )

        mock_post.assert_called_once_with(
            PHISHTANK_API_URL,
            data={
                "url": (
                    "https://bad.example/"
                ),
                "format": "json",
                "app_key": (
                    "fake-test-key"
                ),
            },
            headers={
                "User-Agent": (
                    PHISHTANK_USER_AGENT
                ),
                "Accept": (
                    "application/json"
                ),
            },
            timeout=10,
        )

    @patch(
        "core.phishtank."
        "requests.post"
    )
    def test_not_in_database(
        self,
        mock_post,
    ):
        response = Mock()

        response.status_code = 200
        response.headers = {}

        response.json.return_value = {
            "results": {
                "url": (
                    "https://example.com/"
                ),
                "in_database": False,
                "verified": False,
                "valid": False,
            }
        }

        response.raise_for_status.return_value = (
            None
        )

        mock_post.return_value = (
            response
        )

        result = check_url(
            "https://example.com/",
            api_key="fake-test-key",
        )

        self.assertTrue(
            result["available"]
        )

        self.assertFalse(
            result["listed"]
        )

        self.assertFalse(
            result["matched"]
        )

    @patch(
        "core.phishtank."
        "requests.post"
    )
    def test_unverified_listing_not_match(
        self,
        mock_post,
    ):
        response = Mock()

        response.status_code = 200
        response.headers = {}

        response.json.return_value = {
            "results": {
                "url": (
                    "https://suspect.example/"
                ),
                "in_database": True,
                "verified": False,
                "valid": False,
            }
        }

        response.raise_for_status.return_value = (
            None
        )

        mock_post.return_value = (
            response
        )

        result = check_url(
            "https://suspect.example/",
            api_key="fake-test-key",
        )

        self.assertTrue(
            result["listed"]
        )

        self.assertFalse(
            result["matched"]
        )

    @patch(
        "core.phishtank."
        "requests.post"
    )
    def test_request_without_api_key(
        self,
        mock_post,
    ):
        response = Mock()

        response.status_code = 200
        response.headers = {}

        response.json.return_value = {
            "results": {
                "url": (
                    "https://example.com/"
                ),
                "in_database": False,
                "verified": False,
                "valid": False,
            }
        }

        response.raise_for_status.return_value = (
            None
        )

        mock_post.return_value = (
            response
        )

        check_url(
            "https://example.com/",
            api_key="",
        )

        mock_post.assert_called_once_with(
            PHISHTANK_API_URL,
            data={
                "url": (
                    "https://example.com/"
                ),
                "format": "json",
            },
            headers={
                "User-Agent": (
                    PHISHTANK_USER_AGENT
                ),
                "Accept": (
                    "application/json"
                ),
            },
            timeout=10,
        )

    @patch(
        "core.phishtank."
        "requests.post"
    )
    def test_rate_limit(
        self,
        mock_post,
    ):
        response = Mock()

        response.status_code = 509

        mock_post.return_value = (
            response
        )

        result = check_url(
            "https://example.com/",
            api_key="fake-test-key",
        )

        self.assertFalse(
            result["available"]
        )

        self.assertEqual(
            result["query_status"],
            "rate_limited",
        )

    @patch(
        "core.phishtank."
        "requests.post"
    )
    def test_request_error(
        self,
        mock_post,
    ):
        mock_post.side_effect = (
            requests.RequestException(
                "Test connection failure"
            )
        )

        result = check_url(
            "https://example.com/",
            api_key="fake-test-key",
        )

        self.assertFalse(
            result["available"]
        )

        self.assertEqual(
            result["query_status"],
            "request_error",
        )

    @patch(
        "core.phishtank."
        "requests.post"
    )
    def test_invalid_json(
        self,
        mock_post,
    ):
        response = Mock()

        response.status_code = 200
        response.headers = {}

        response.raise_for_status.return_value = (
            None
        )

        response.json.side_effect = (
            ValueError()
        )

        mock_post.return_value = (
            response
        )

        result = check_url(
            "https://example.com/",
            api_key="fake-test-key",
        )

        self.assertFalse(
            result["available"]
        )

        self.assertEqual(
            result["query_status"],
            "invalid_json",
        )


if __name__ == "__main__":
    unittest.main()