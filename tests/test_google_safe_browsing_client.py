import base64
import unittest

from unittest.mock import (
    Mock,
    patch,
)

import requests

from core.google_safe_browsing import (
    build_hash_candidates,
)

from core.google_safe_browsing_cache import (
    SafeBrowsingCache,
)

from core.google_safe_browsing_client import (
    GOOGLE_HASHES_SEARCH_URL,
    has_enforceable_match,
    GoogleSafeBrowsingHttpError,
    parse_cache_duration,
    request_full_hashes,
    search_hash_candidates,
    validate_full_hash_detail,
)


def encode_varint(value):
    output = bytearray()

    while True:
        byte = value & 0x7F
        value >>= 7

        if value:
            output.append(byte | 0x80)
        else:
            output.append(byte)
            return bytes(output)


def encode_field(number, value):
    if isinstance(value, int):
        return (
            encode_varint(number << 3)
            + encode_varint(value)
        )

    return (
        encode_varint((number << 3) | 2)
        + encode_varint(len(value))
        + value
    )


def protobuf_reply(
    full_hash,
    threat_type,
    cache_seconds,
):
    detail = encode_field(1, threat_type)

    full_hash_message = (
        encode_field(1, full_hash)
        + encode_field(2, detail)
    )

    return (
        encode_field(1, full_hash_message)
        + encode_field(
            2,
            encode_field(1, cache_seconds),
        )
    )


def fake_http_response(
    status_code,
    content,
    content_type="application/x-protobuf",
):
    response = Mock()
    response.status_code = status_code
    response.content = content
    response.headers = {
        "Content-Type": content_type,
    }

    return response


class TestGoogleSafeBrowsingClient(
    unittest.TestCase
):

    def configure_google_mock(
        self,
        mock_request,
        payload=None,
        side_effect=None,
    ):
        if side_effect is not None:
            mock_request.side_effect = (
                side_effect
            )
        else:
            mock_request.return_value = (
                payload
            )

        return mock_request

    def test_missing_api_key(self):
        candidates = build_hash_candidates(
            "http://example.com/"
        )

        cache = SafeBrowsingCache()

        result = search_hash_candidates(
            candidates,
            api_key="",
            cache=cache,
        )

        self.assertFalse(
            result["available"]
        )

        self.assertFalse(
            result["matched"]
        )

        self.assertEqual(
            result["query_status"],
            "missing_api_key",
        )

    @patch(
        "core.google_safe_browsing_client."
        "request_full_hashes"
    )

    def test_no_match(
        self,
        mock_request,
    ):

        self.configure_google_mock(
            mock_request,
            payload={
                "fullHashes": [],
                "cacheDuration": "300s",
            },
        )

        candidates = build_hash_candidates(
            "http://example.com/"
        )

        cache = SafeBrowsingCache()

        result = search_hash_candidates(
            candidates,
            api_key="fake-test-key",
            cache=cache,
        )

        self.assertTrue(
            result["available"]
        )

        self.assertFalse(
            result["matched"]
        )

        self.assertEqual(
            result["query_status"],
            "ok",
        )

        self.assertEqual(
            result["cache_duration"],
            "300s",
        )

        self.assertTrue(
            result["network_request_made"]
        )

        self.assertEqual(
            result["cache_status"],
            "miss",
        )

    @patch(
        "core.google_safe_browsing_client."
        "request_full_hashes"
    )
    def test_confirmed_full_hash_match(
        self,
        mock_request,
    ):
        candidates = build_hash_candidates(
            "http://example.com/"
        )

        candidate = candidates[0]

        full_hash_b64 = (
            base64.b64encode(
                candidate["full_hash"]
            ).decode("ascii")
        )

        self.configure_google_mock(
            mock_request,
            payload={
               "fullHashes": [
                {
                   "fullHash": (
                        full_hash_b64
                    ),
                    "fullHashDetails": [
                        {
                            "threatType": (
                                "SOCIAL_ENGINEERING"
                            ),
                            "attributes": [],
                        }
                    ],
                }
            ],
            "cacheDuration": "300s",
        },
    )

        cache = SafeBrowsingCache()

        result = search_hash_candidates(
            candidates,
            api_key="fake-test-key",
            cache=cache,
        )

        self.assertTrue(
            result["matched"]
        )

        self.assertEqual(
            len(result["matches"]),
            1,
        )

        self.assertEqual(
            result["matches"][0][
                "expression"
            ],
            candidate["expression"],
        )

    @patch(
        "core.google_safe_browsing_client."
        "request_full_hashes"
    )
    def test_prefix_collision_is_not_match(
        self,
        mock_request,
    ):
        candidates = build_hash_candidates(
            "http://example.com/"
        )

        candidate = candidates[0]

        fake_full_hash = (
            candidate["prefix"]
            + (b"\x00" * 28)
        )

        self.assertNotEqual(
            fake_full_hash,
            candidate["full_hash"],
        )

        self.configure_google_mock(
            mock_request,
            payload={
                "fullHashes": [
                   {
                        "fullHash": (
                            base64.b64encode(
                                fake_full_hash
                            ).decode("ascii")
                        ),
                        "fullHashDetails": [],
                    }
                ],
                "cacheDuration": "300s",
            },
        )

        cache = SafeBrowsingCache()

        result = search_hash_candidates(
            candidates,
            api_key="fake-test-key",
            cache=cache,
        )

        self.assertFalse(
            result["matched"]
        )

    @patch(
        "core.google_safe_browsing_client."
        "request_full_hashes"
    )
    def test_invalid_response_fails_gracefully(
        self,
        mock_request,
    ):
        self.configure_google_mock(
            mock_request,
            side_effect=ValueError(
                "Invalid response"
            ),
        )

        candidates = build_hash_candidates(
            "http://example.com/"
        )

        cache = SafeBrowsingCache()

        result = search_hash_candidates(
            candidates,
            api_key="fake-test-key",
            cache=cache,
        )

        self.assertFalse(
            result["available"]
        )

        self.assertFalse(
            result["matched"]
        )

        self.assertEqual(
            result["query_status"],
            "invalid_response",
        )

    def test_parse_fractional_cache_duration(
        self,
    ):
        self.assertEqual(
            parse_cache_duration(
                "3.5s"
            ),
            3.5,
        )

    def test_invalid_cache_duration(self):
        self.assertEqual(
            parse_cache_duration(
                "banana"
            ),
            0.0,
        )

    def test_unknown_threat_type_is_discarded(
        self,
    ):
        detail = {
            "threatType": (
                "NEW_UNKNOWN_THREAT"
            ),
            "attributes": [],
        }

        self.assertIsNone(
            validate_full_hash_detail(
                detail
            )
        )

    def test_unknown_attribute_is_discarded(
        self,
    ):
        detail = {
            "threatType": (
                "SOCIAL_ENGINEERING"
            ),
            "attributes": [
                "UNKNOWN_ATTRIBUTE"
            ],
        }

        self.assertIsNone(
            validate_full_hash_detail(
                detail
            )
        )

    def test_valid_threat_detail_is_retained(
        self,
    ):
        detail = {
            "threatType": (
                "SOCIAL_ENGINEERING"
            ),
            "attributes": [],
        }

        self.assertEqual(
            validate_full_hash_detail(
                detail
            ),
            detail,
        )

    @patch(
        "core.google_safe_browsing_client."
        "request_full_hashes"
    )
    def test_cached_result_skips_network(
        self,
        mock_request,
    ):
        candidates = build_hash_candidates(
            "http://example.com/"
        )

        cache = SafeBrowsingCache()

        for candidate in candidates:
            cache.set(
                candidate["prefix_b64"],
                [],
                300,
            )

        result = search_hash_candidates(
            candidates,
            api_key="fake-test-key",
            cache=cache,
        )

        mock_request.assert_not_called()

        self.assertFalse(
            result[
                "network_request_made"
            ]
        )

        self.assertEqual(
            result["cache_status"],
            "hit",
        )

        self.assertFalse(
            result["matched"]
        )

    @patch(
        "core.google_safe_browsing_client."
        "request_full_hashes"
    )
    def test_http_error_reports_google_message(
        self,
        mock_request,
    ):
        self.configure_google_mock(
            mock_request,
            side_effect=GoogleSafeBrowsingHttpError(
                400,
                "API key not valid.",
            ),
        )

        candidates = build_hash_candidates(
            "http://example.com/"
        )

        result = search_hash_candidates(
            candidates,
            api_key="fake-test-key",
            cache=SafeBrowsingCache(),
        )

        self.assertFalse(
            result["available"]
        )

        self.assertEqual(
            result["query_status"],
            "http_error",
        )

        self.assertEqual(
            result["http_status"],
            400,
        )

        self.assertEqual(
            result["error_message"],
            "API key not valid.",
        )

    @patch(
        "core.google_safe_browsing_client."
        "request_full_hashes"
    )
    def test_network_error_reports_error_type(
        self,
        mock_request,
    ):
        self.configure_google_mock(
            mock_request,
            side_effect=requests.ConnectionError(
                "no route"
            ),
        )

        candidates = build_hash_candidates(
            "http://example.com/"
        )

        result = search_hash_candidates(
            candidates,
            api_key="fake-test-key",
            cache=SafeBrowsingCache(),
        )

        self.assertFalse(
            result["available"]
        )

        self.assertEqual(
            result["query_status"],
            "network_error",
        )

        self.assertEqual(
            result["error_type"],
            "ConnectionError",
        )

    @patch(
        "core.google_safe_browsing_client."
        "requests.get"
    )
    def test_request_sends_prefixes_and_key_header(
        self,
        mock_get,
    ):
        mock_get.return_value = (
            fake_http_response(
                200,
                encode_field(
                    2,
                    encode_field(1, 300),
                ),
            )
        )

        payload = request_full_hashes(
            ["AAAAAA==", "BBBBBB=="],
            "fake-test-key",
            timeout=7,
        )

        self.assertEqual(
            payload,
            {
                "fullHashes": [],
                "cacheDuration": "300s",
            },
        )

        args, kwargs = mock_get.call_args

        self.assertEqual(
            args[0],
            GOOGLE_HASHES_SEARCH_URL,
        )

        self.assertEqual(
            kwargs["params"],
            {
                "hashPrefixes": [
                    "AAAAAA==",
                    "BBBBBB==",
                ],
            },
        )

        self.assertEqual(
            kwargs["headers"][
                "x-goog-api-key"
            ],
            "fake-test-key",
        )

        self.assertNotIn(
            "alt",
            kwargs["params"],
        )

        self.assertEqual(
            kwargs["timeout"],
            7,
        )

    @patch(
        "core.google_safe_browsing_client."
        "requests.get"
    )
    def test_request_raises_http_error_with_message(
        self,
        mock_get,
    ):
        mock_get.return_value = (
            fake_http_response(
                403,
                (
                    b'{"error": {"code": 403, '
                    b'"message": "Safe Browsing API '
                    b'is disabled."}}'
                ),
                "application/json; charset=UTF-8",
            )
        )

        with self.assertRaises(
            GoogleSafeBrowsingHttpError
        ) as context:
            request_full_hashes(
                ["AAAAAA=="],
                "fake-test-key",
            )

        self.assertEqual(
            context.exception.status_code,
            403,
        )

        self.assertEqual(
            context.exception.message,
            "Safe Browsing API is disabled.",
        )

    @patch(
        "core.google_safe_browsing_client."
        "requests.get"
    )
    def test_protobuf_reply_end_to_end_match(
        self,
        mock_get,
    ):
        candidates = build_hash_candidates(
            "http://example.com/"
        )

        candidate = candidates[0]

        mock_get.return_value = (
            fake_http_response(
                200,
                protobuf_reply(
                    candidate["full_hash"],
                    threat_type=2,
                    cache_seconds=300,
                ),
            )
        )

        cache = SafeBrowsingCache()

        result = search_hash_candidates(
            candidates,
            api_key="fake-test-key",
            cache=cache,
        )

        self.assertTrue(
            result["available"]
        )

        self.assertTrue(
            result["matched"]
        )

        self.assertEqual(
            result["cache_duration"],
            "300s",
        )

        self.assertEqual(
            result["matches"][0]["details"],
            [
                {
                    "threatType": (
                        "SOCIAL_ENGINEERING"
                    ),
                    "attributes": [],
                }
            ],
        )

        second = search_hash_candidates(
            candidates,
            api_key="fake-test-key",
            cache=cache,
        )

        self.assertEqual(
            mock_get.call_count,
            1,
        )

        self.assertTrue(
            second["matched"]
        )

        self.assertEqual(
            second["cache_status"],
            "hit",
        )

    @patch(
        "core.google_safe_browsing_client."
        "requests.get"
    )
    def test_garbage_reply_is_invalid_response(
        self,
        mock_get,
    ):
        mock_get.return_value = (
            fake_http_response(
                200,
                b"<html>not protobuf</html>",
                "text/html",
            )
        )

        candidates = build_hash_candidates(
            "http://example.com/"
        )

        result = search_hash_candidates(
            candidates,
            api_key="fake-test-key",
            cache=SafeBrowsingCache(),
        )

        self.assertEqual(
            result["query_status"],
            "invalid_response",
        )


    def reply_for_first_candidate(self, mock_request, details):
        candidates = build_hash_candidates("http://example.com/")

        full_hash_b64 = base64.b64encode(
            candidates[0]["full_hash"]
        ).decode("ascii")

        full_hash = {"fullHash": full_hash_b64}

        if details is not None:
            full_hash["fullHashDetails"] = details

        self.configure_google_mock(
            mock_request,
            payload={
                "fullHashes": [full_hash],
                "cacheDuration": "300s",
            },
        )

        return search_hash_candidates(
            candidates,
            api_key="fake-test-key",
            cache=SafeBrowsingCache(),
        )

    @patch("core.google_safe_browsing_client.request_full_hashes")
    def test_full_hash_without_valid_details_is_not_a_match(self, mock_request):
        for details in (None, [], [{"threatType": "NOT_A_REAL_TYPE"}]):
            result = self.reply_for_first_candidate(mock_request, details)

            self.assertFalse(result["matched"], details)
            self.assertEqual(result["matches"], [])

    @patch("core.google_safe_browsing_client.request_full_hashes")
    def test_canary_match_is_reported_but_not_enforceable(self, mock_request):
        result = self.reply_for_first_candidate(
            mock_request,
            [{"threatType": "SOCIAL_ENGINEERING", "attributes": ["CANARY"]}],
        )

        self.assertTrue(result["matched"])
        self.assertFalse(has_enforceable_match(result))

    def test_has_enforceable_match(self):
        def result(*details):
            return {"matches": [{"details": list(details)}]}

        self.assertTrue(has_enforceable_match(result({"threatType": "MALWARE", "attributes": []})))
        self.assertFalse(has_enforceable_match(result({"threatType": "MALWARE", "attributes": ["FRAME_ONLY"]})))
        self.assertTrue(
            has_enforceable_match(
                result(
                    {"threatType": "MALWARE", "attributes": ["CANARY"]},
                    {"threatType": "MALWARE", "attributes": []},
                )
            )
        )
        self.assertFalse(has_enforceable_match({}))
        self.assertFalse(has_enforceable_match(None))


if __name__ == "__main__":
    unittest.main()