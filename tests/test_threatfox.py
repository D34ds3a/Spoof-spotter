import os
import unittest
from unittest.mock import patch, Mock

import requests

from core.threatfox import (
    THREATFOX_API_URL,
    THREATFOX_AUTH_ENV,
    get_auth_key,
    search_ioc,
)

class TestThreatFox(unittest.TestCase):

    def test_get_auth_key(self):
        with patch.dict(
            os.environ,
            {
                THREATFOX_AUTH_ENV: "fake-test-key"
            },
        ):
            key = get_auth_key()

        self.assertEqual(
            key,
            "fake-test-key"
        )

    def test_missing_auth_key(self):
        with patch(
            "core.threatfox.get_auth_key",
            return_value="",
        ):
            result = search_ioc(
                "example.com"
            )

        self.assertFalse(result["available"])

        self.assertFalse(result["matched"])

        self.assertEqual(
            result["query_status"],
            "missing_auth_key"
        )

    def test_empty_search(self):
        result = search_ioc("")

        self.assertTrue(result["available"])

        self.assertFalse(result["matched"])

        self.assertEqual(result["query_status"],"empty_search")

    @patch("core.threatfox.requests.post")
    def test_successful_ioc_match(
        self,
        mock_post
    ):
        mock_response = Mock()

        mock_response.json.return_value = {
            "query_status": "ok",
            "data": [
                {
                    "ioc": "bad-example.com",
                    "ioc_type": "domain",
                    "threat_type": "botnet_cc",
                    "threat_type_desc": "Botnet command and control",
                    "malware_printable": "Test Malware",
                    "confidence_level": 90,
                    "first_seen": "2026-09-25 12:00:00",
                    "last_seen": "2026-09-26 12:00:00",
                    "reference": "https://example.test",
                    "is_compromised": False,
                }
            ],
        }

        mock_post.return_value = mock_response

        result = search_ioc(
            "bad-example.com",
            auth_key="fake-test-key",
        )

        self.assertTrue(
            result["available"]
        )

        self.assertTrue(
            result["matched"]
        )

        self.assertEqual(
            result["source"],
            "ThreatFox"
        )

        self.assertEqual(
            result["results"][0]["ioc"],
            "bad-example.com"
        )

        self.assertEqual(
            result["results"][0]["confidence"],
            90
        )

        mock_post.assert_called_once_with(
            THREATFOX_API_URL,
            headers={
                "Auth-Key": "fake-test-key"
            },
            json={
                "query": "search_ioc",
                "search_term": "bad-example.com",
                "exact_match": True,
            },
            timeout=10,
        )

    @patch("core.threatfox.requests.post")
    def test_no_ioc_match(
        self,
        mock_post
    ):
        mock_response = Mock()

        mock_response.json.return_value = {
            "query_status": "no_result",
            "data": [],
        }

        mock_post.return_value = mock_response

        result = search_ioc(
            "clean-example.com",
            auth_key="fake-test-key",
        )

        self.assertTrue(
            result["available"]
        )

        self.assertFalse(
            result["matched"]
        )

        self.assertEqual(
            result["results"],
            []
        )

    @patch("core.threatfox.requests.post")
    def test_request_error(
        self,
        mock_post
    ):
        mock_post.side_effect = (
            requests.RequestException(
                "Test connection failure"
            )
        )

        result = search_ioc(
            "example.com",
            auth_key="fake-test-key",
        )

        self.assertFalse(
            result["available"]
        )

        self.assertFalse(
            result["matched"]
        )

        self.assertEqual(
            result["query_status"],
            "request_error"
        )

if __name__ == "__main__":
    unittest.main()