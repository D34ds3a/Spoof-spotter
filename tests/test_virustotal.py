import base64
import unittest

from unittest.mock import (
    Mock,
    patch,
)

import requests

from core.virustotal import (
    VIRUSTOTAL_API_URL,
    ascii_domain,
    lookup,
    url_identifier,
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


def report_payload(
    malicious=0,
    suspicious=0,
    harmless=70,
    undetected=20,
    results=None,
    object_id="abc123",
):
    return {
        "data": {
            "id": object_id,
            "type": "url",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "timeout": 0,
                },
                "last_analysis_results": results or {},
                "last_analysis_date": 1790000000,
                "reputation": -5,
            },
        }
    }


class TestVirusTotalHelpers(
    unittest.TestCase
):

    def test_url_identifier_is_unpadded_urlsafe_base64(self):
        url = "http://www.example.com/path?q=1"

        identifier = url_identifier(url)

        self.assertNotIn("=", identifier)

        padded = identifier + "=" * (-len(identifier) % 4)

        self.assertEqual(
            base64.urlsafe_b64decode(padded).decode("utf-8"),
            url,
        )

    def test_international_domain_converted(self):
        self.assertEqual(
            ascii_domain("Bücher.example."),
            "xn--bcher-kva.example",
        )


class TestVirusTotalLookup(
    unittest.TestCase
):

    def test_unknown_lookup_type_rejected(self):
        with self.assertRaises(ValueError):
            lookup(
                "example.com",
                "file",
                api_key="test-key",
            )

    def test_empty_indicator(self):
        result = lookup(
            "",
            "domain",
            api_key="test-key",
        )

        self.assertEqual(
            result["query_status"],
            "empty_indicator",
        )

        self.assertFalse(result["matched"])

    @patch("core.virustotal.requests.get")
    def test_missing_api_key(self, mock_get):
        result = lookup(
            "example.com",
            "domain",
            api_key="",
        )

        self.assertFalse(result["available"])

        self.assertEqual(
            result["query_status"],
            "missing_api_key",
        )

        mock_get.assert_not_called()

    @patch("core.virustotal.requests.get")
    def test_url_lookup_request_format(self, mock_get):
        mock_get.return_value = fake_response(
            200,
            report_payload(),
        )

        url = "https://login.example.com/verify"

        lookup(
            url,
            "url",
            api_key="test-key",
            timeout=7,
        )

        args, kwargs = mock_get.call_args

        self.assertEqual(
            args[0],
            f"{VIRUSTOTAL_API_URL}/urls/"
            f"{url_identifier(url)}",
        )

        self.assertEqual(
            kwargs["headers"]["x-apikey"],
            "test-key",
        )

        self.assertNotIn("test-key", args[0])

        self.assertEqual(kwargs["timeout"], 7)

    @patch("core.virustotal.requests.get")
    def test_domain_lookup_request_format(self, mock_get):
        mock_get.return_value = fake_response(
            200,
            report_payload(),
        )

        result = lookup(
            "Sub.Example.COM",
            "domain",
            api_key="test-key",
        )

        self.assertEqual(
            mock_get.call_args[0][0],
            f"{VIRUSTOTAL_API_URL}/domains/sub.example.com",
        )

        self.assertEqual(
            result["report_link"],
            "https://www.virustotal.com/gui/domain/sub.example.com",
        )

    @patch("core.virustotal.requests.get")
    def test_phishing_verdict_is_flagged(self, mock_get):
        mock_get.return_value = fake_response(
            200,
            report_payload(
                malicious=3,
                suspicious=1,
                results={
                    "EngineB": {
                        "category": "malicious",
                        "result": "phishing",
                        "engine_name": "Engine B",
                    },
                    "EngineA": {
                        "category": "malicious",
                        "result": "Phishing",
                        "engine_name": "Engine A",
                    },
                    "EngineC": {
                        "category": "malicious",
                        "result": "malware",
                        "engine_name": "Engine C",
                    },
                    "EngineD": {
                        "category": "harmless",
                        "result": "clean",
                        "engine_name": "Engine D",
                    },
                },
                object_id="sha256id",
            ),
        )

        result = lookup(
            "https://bad.example/login",
            "url",
            api_key="test-key",
        )

        self.assertTrue(result["available"])
        self.assertTrue(result["matched"])

        self.assertEqual(
            result["query_status"],
            "ok",
        )

        self.assertEqual(
            result["phishing_vendors"],
            ["Engine A", "Engine B"],
        )

        self.assertEqual(
            result["stats"]["malicious"],
            3,
        )

        self.assertEqual(
            result["engines_total"],
            94,
        )

        self.assertEqual(result["reputation"], -5)

        self.assertEqual(
            result["last_analysis_date"],
            "2026-09-21 14:13 UTC",
        )

        self.assertEqual(
            result["report_link"],
            "https://www.virustotal.com/gui/url/sha256id",
        )

    @patch("core.virustotal.requests.get")
    def test_clean_report_is_not_flagged(self, mock_get):
        mock_get.return_value = fake_response(
            200,
            report_payload(),
        )

        result = lookup(
            "example.com",
            "domain",
            api_key="test-key",
        )

        self.assertTrue(result["available"])
        self.assertFalse(result["matched"])
        self.assertEqual(result["phishing_vendors"], [])

    @patch("core.virustotal.requests.get")
    def test_not_found_is_available_but_not_matched(self, mock_get):
        mock_get.return_value = fake_response(
            404,
            {
                "error": {
                    "code": "NotFoundError",
                    "message": "not found",
                }
            },
        )

        result = lookup(
            "https://new.example/",
            "url",
            api_key="test-key",
        )

        self.assertTrue(result["available"])
        self.assertFalse(result["matched"])

        self.assertEqual(
            result["query_status"],
            "not_found",
        )

    @patch("core.virustotal.requests.get")
    def test_rate_limit(self, mock_get):
        mock_get.return_value = fake_response(
            429,
            {
                "error": {
                    "code": "QuotaExceededError",
                    "message": "Quota exceeded",
                }
            },
        )

        result = lookup(
            "example.com",
            "domain",
            api_key="test-key",
        )

        self.assertFalse(result["available"])

        self.assertEqual(
            result["query_status"],
            "rate_limited",
        )

    @patch("core.virustotal.requests.get")
    def test_wrong_key(self, mock_get):
        mock_get.return_value = fake_response(
            401,
            {
                "error": {
                    "code": "WrongCredentialsError",
                    "message": "Wrong API key",
                }
            },
        )

        result = lookup(
            "example.com",
            "domain",
            api_key="bad-key",
        )

        self.assertFalse(result["available"])

        self.assertEqual(
            result["query_status"],
            "authentication_error",
        )

        self.assertEqual(
            result["error_message"],
            "Wrong API key",
        )

    @patch("core.virustotal.requests.get")
    def test_network_error(self, mock_get):
        mock_get.side_effect = requests.ConnectionError(
            "no route"
        )

        result = lookup(
            "example.com",
            "domain",
            api_key="test-key",
        )

        self.assertFalse(result["available"])

        self.assertEqual(
            result["query_status"],
            "request_error",
        )

        self.assertEqual(
            result["error_type"],
            "ConnectionError",
        )

    @patch("core.virustotal.requests.get")
    def test_invalid_json(self, mock_get):
        mock_get.return_value = fake_response(200)

        result = lookup(
            "example.com",
            "domain",
            api_key="test-key",
        )

        self.assertEqual(
            result["query_status"],
            "invalid_json",
        )

    @patch("core.virustotal.requests.get")
    def test_unexpected_response_shape(self, mock_get):
        mock_get.return_value = fake_response(
            200,
            ["not", "a", "report"],
        )

        result = lookup(
            "example.com",
            "domain",
            api_key="test-key",
        )

        self.assertEqual(
            result["query_status"],
            "invalid_response",
        )

    @patch("core.virustotal.get_credential")
    @patch("core.virustotal.requests.get")
    def test_uses_stored_credential(self, mock_get, mock_credential):
        mock_credential.return_value = "stored-key"

        mock_get.return_value = fake_response(
            200,
            report_payload(),
        )

        lookup(
            "example.com",
            "domain",
        )

        mock_credential.assert_called_once_with(
            "virustotal"
        )

        self.assertEqual(
            mock_get.call_args[1]["headers"]["x-apikey"],
            "stored-key",
        )


if __name__ == "__main__":
    unittest.main()
