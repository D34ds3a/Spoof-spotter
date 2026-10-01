import unittest

from unittest.mock import (
    Mock,
    patch,
)

import requests

from core.urlhaus import (
    URLHAUS_API_URL,
    lookup,
)


def fake_response(status_code, payload=None):
    response = Mock()
    response.status_code = status_code

    if payload is None:
        response.json.side_effect = ValueError(
            "no JSON"
        )
    else:
        response.json.return_value = payload

    return response


URL_MATCH = {
    "query_status": "ok",
    "id": "123",
    "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/",
    "url": "http://bad.example/payload.exe",
    "url_status": "online",
    "host": "bad.example",
    "date_added": "2026-09-29 10:00:00 UTC",
    "last_online": "2026-09-30 08:00:00 UTC",
    "threat": "malware_download",
    "blacklists": {
        "spamhaus_dbl": "abused_legit_malware",
        "surbl": "not listed",
    },
    "tags": ["exe", "ClearFake"],
    "payloads": [],
}

HOST_MATCH = {
    "query_status": "ok",
    "urlhaus_reference": "https://urlhaus.abuse.ch/host/bad.example/",
    "host": "bad.example",
    "firstseen": "2026-09-01 10:00:00 UTC",
    "url_count": "3",
    "blacklists": {
        "spamhaus_dbl": "not listed",
        "surbl": "listed",
    },
    "urls": [
        {
            "url": "http://bad.example/a.exe",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["exe"],
        },
        {
            "url": "http://bad.example/b.zip",
            "url_status": "offline",
            "threat": "malware_download",
            "tags": ["zip", "exe"],
        },
        {
            "url": "http://bad.example/c.js",
            "url_status": "online",
            "threat": "malware_download",
            "tags": None,
        },
    ],
}


class TestURLhaus(
    unittest.TestCase
):

    def test_unknown_lookup_type_rejected(self):
        with self.assertRaises(ValueError):
            lookup(
                "bad.example",
                "file",
                auth_key="test-key",
            )

    def test_empty_indicator(self):
        result = lookup(
            " ",
            "url",
            auth_key="test-key",
        )

        self.assertEqual(
            result["query_status"],
            "empty_indicator",
        )

    @patch("core.urlhaus.requests.post")
    def test_missing_auth_key(self, mock_post):
        result = lookup(
            "bad.example",
            "domain",
            auth_key="",
        )

        self.assertFalse(result["available"])

        self.assertEqual(
            result["query_status"],
            "missing_auth_key",
        )

        mock_post.assert_not_called()

    @patch("core.urlhaus.get_credential")
    @patch("core.urlhaus.requests.post")
    def test_shares_threatfox_auth_key(self, mock_post, mock_credential):
        mock_credential.return_value = "abusech-key"

        mock_post.return_value = fake_response(
            200,
            {"query_status": "no_results"},
        )

        lookup(
            "example.com",
            "domain",
        )

        mock_credential.assert_called_once_with(
            "threatfox"
        )

        self.assertEqual(
            mock_post.call_args[1]["headers"]["Auth-Key"],
            "abusech-key",
        )

    @patch("core.urlhaus.requests.post")
    def test_url_match(self, mock_post):
        mock_post.return_value = fake_response(
            200,
            URL_MATCH,
        )

        result = lookup(
            "http://bad.example/payload.exe",
            "url",
            auth_key="test-key",
            timeout=7,
        )

        args, kwargs = mock_post.call_args

        self.assertEqual(
            args[0],
            f"{URLHAUS_API_URL}/url/",
        )

        self.assertEqual(
            kwargs["data"],
            {"url": "http://bad.example/payload.exe"},
        )

        self.assertEqual(kwargs["timeout"], 7)

        self.assertTrue(result["available"])
        self.assertTrue(result["matched"])

        details = result["details"]

        self.assertEqual(details["url_status"], "online")
        self.assertEqual(details["threat"], "malware_download")
        self.assertEqual(details["tags"], ["ClearFake", "exe"])

        self.assertEqual(
            details["blocklists"],
            ["Spamhaus DBL (abused_legit_malware)"],
        )

    @patch("core.urlhaus.requests.post")
    def test_host_match_summary(self, mock_post):
        mock_post.return_value = fake_response(
            200,
            HOST_MATCH,
        )

        result = lookup(
            "Bad.Example",
            "domain",
            auth_key="test-key",
        )

        args, kwargs = mock_post.call_args

        self.assertEqual(
            args[0],
            f"{URLHAUS_API_URL}/host/",
        )

        self.assertEqual(
            kwargs["data"],
            {"host": "bad.example"},
        )

        details = result["details"]

        self.assertTrue(result["matched"])
        self.assertEqual(details["url_count"], 3)
        self.assertEqual(details["online_url_count"], 2)
        self.assertEqual(details["threats"], ["malware_download"])
        self.assertEqual(details["tags"], ["exe", "zip"])
        self.assertEqual(details["blocklists"], ["SURBL (listed)"])

    @patch("core.urlhaus.requests.post")
    def test_no_results(self, mock_post):
        mock_post.return_value = fake_response(
            200,
            {"query_status": "no_results"},
        )

        result = lookup(
            "example.com",
            "domain",
            auth_key="test-key",
        )

        self.assertTrue(result["available"])
        self.assertFalse(result["matched"])

        self.assertEqual(
            result["query_status"],
            "no_results",
        )

    @patch("core.urlhaus.requests.post")
    def test_invalid_url_reply(self, mock_post):
        mock_post.return_value = fake_response(
            200,
            {"query_status": "invalid_url"},
        )

        result = lookup(
            "https://",
            "url",
            auth_key="test-key",
        )

        self.assertFalse(result["matched"])

        self.assertEqual(
            result["query_status"],
            "invalid_url",
        )

    @patch("core.urlhaus.requests.post")
    def test_unknown_query_status_is_unavailable(self, mock_post):
        mock_post.return_value = fake_response(
            200,
            {"query_status": "unknown_auth_key"},
        )

        result = lookup(
            "example.com",
            "domain",
            auth_key="bad-key",
        )

        self.assertFalse(result["available"])

        self.assertEqual(
            result["query_status"],
            "unknown_auth_key",
        )

    @patch("core.urlhaus.requests.post")
    def test_rejected_key(self, mock_post):
        mock_post.return_value = fake_response(401)

        result = lookup(
            "example.com",
            "domain",
            auth_key="bad-key",
        )

        self.assertEqual(
            result["query_status"],
            "authentication_error",
        )

    @patch("core.urlhaus.requests.post")
    def test_network_error(self, mock_post):
        mock_post.side_effect = requests.Timeout(
            "slow"
        )

        result = lookup(
            "example.com",
            "domain",
            auth_key="test-key",
        )

        self.assertFalse(result["available"])

        self.assertEqual(
            result["query_status"],
            "request_error",
        )

        self.assertEqual(
            result["error_type"],
            "Timeout",
        )

    @patch("core.urlhaus.requests.post")
    def test_invalid_json(self, mock_post):
        mock_post.return_value = fake_response(200)

        result = lookup(
            "example.com",
            "domain",
            auth_key="test-key",
        )

        self.assertEqual(
            result["query_status"],
            "invalid_json",
        )


if __name__ == "__main__":
    unittest.main()
