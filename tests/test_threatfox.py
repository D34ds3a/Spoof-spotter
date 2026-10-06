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
        mock_response.status_code = 200

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
            allow_redirects=False,
        )

    @patch("core.threatfox.requests.post")
    def test_no_ioc_match(
        self,
        mock_post
    ):
        mock_response = Mock()
        mock_response.status_code = 200

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


    def threatfox_reply(self, mock_post, payload):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = payload
        mock_post.return_value = mock_response

    @patch("core.threatfox.requests.post")
    def test_rejected_query_is_unavailable(self, mock_post):
        self.threatfox_reply(mock_post, {"query_status": "unknown_auth_key"})

        result = search_ioc("example.net", auth_key="fake-test-key")

        self.assertFalse(result["available"])
        self.assertFalse(result["matched"])
        self.assertEqual(result["query_status"], "unknown_auth_key")

    @patch("core.threatfox.requests.post")
    def test_no_result_is_available(self, mock_post):
        self.threatfox_reply(mock_post, {"query_status": "no_result", "data": "Your search did not yield any results"})

        result = search_ioc("example.net", auth_key="fake-test-key")

        self.assertTrue(result["available"])
        self.assertFalse(result["matched"])

    @patch("core.threatfox.requests.post")
    def test_non_dict_reply_is_invalid(self, mock_post):
        self.threatfox_reply(mock_post, ["not", "a", "dict"])

        result = search_ioc("example.net", auth_key="fake-test-key")

        self.assertFalse(result["available"])
        self.assertEqual(result["query_status"], "invalid_response")

    @patch("core.threatfox.requests.post")
    def test_non_dict_rows_are_ignored(self, mock_post):
        self.threatfox_reply(
            mock_post,
            {
                "query_status": "ok",
                "data": [
                    "not a row",
                    {"ioc": "bad-example.com", "ioc_type": "domain", "confidence_level": 50},
                ],
            },
        )

        result = search_ioc("bad-example.com", auth_key="fake-test-key")

        self.assertTrue(result["matched"])
        self.assertEqual(len(result["results"]), 1)

    @patch("core.threatfox.requests.post")
    def test_all_rows_malformed_is_invalid(self, mock_post):
        self.threatfox_reply(mock_post, {"query_status": "ok", "data": ["x", 42]})

        result = search_ioc("example.net", auth_key="fake-test-key")

        self.assertFalse(result["available"])
        self.assertEqual(result["query_status"], "invalid_response")

    @patch("core.threatfox.requests.post")
    def test_rejected_key_is_authentication_error(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 401
        mock_post.return_value = mock_response

        result = search_ioc("example.net", auth_key="bad-key")

        self.assertFalse(result["available"])
        self.assertEqual(result["query_status"], "authentication_error")

    @patch("core.threatfox.requests.post")
    def test_redirect_is_not_followed_or_parsed(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 302
        mock_response.json.return_value = {"query_status": "ok", "data": []}
        mock_post.return_value = mock_response

        result = search_ioc("example.net", auth_key="fake-test-key")

        self.assertFalse(result["available"])
        self.assertEqual(result["query_status"], "http_error")
        self.assertEqual(result["http_status"], 302)

    @patch("core.threatfox.requests.post")
    def test_request_error_reports_type_only(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("details that should not be shown")

        result = search_ioc("example.net", auth_key="fake-test-key")

        self.assertEqual(result["error_type"], "ConnectionError")
        self.assertNotIn("error", result)


if __name__ == "__main__":
    unittest.main()