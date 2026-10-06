import base64
import hashlib
import unittest

from core.google_safe_browsing_protobuf import (
    ProtobufDecodeError,
    decode_search_hashes_response,
    describe_error_body,
    format_duration,
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


def duration(seconds, nanos=0):
    message = encode_field(1, seconds)

    if nanos:
        message += encode_field(2, nanos)

    return message


PHISHING_HASH = hashlib.sha256(
    b"testsafebrowsing.appspot.com/s/phishing.html"
).digest()


class TestGoogleSafeBrowsingProtobuf(
    unittest.TestCase
):

    def test_no_match_reply(self):
        body = encode_field(
            2,
            duration(300),
        )

        self.assertEqual(
            decode_search_hashes_response(
                body
            ),
            {
                "fullHashes": [],
                "cacheDuration": "300s",
            },
        )

    def test_empty_body_is_no_match(self):
        self.assertEqual(
            decode_search_hashes_response(
                b""
            ),
            {
                "fullHashes": [],
            },
        )

    def test_match_with_packed_attributes(self):
        packed = encode_varint(1) + encode_varint(2)

        detail = (
            encode_field(1, 1)
            + encode_field(2, packed)
        )

        full_hash = (
            encode_field(1, PHISHING_HASH)
            + encode_field(2, detail)
        )

        body = (
            encode_field(1, full_hash)
            + encode_field(2, duration(60))
        )

        result = decode_search_hashes_response(
            body
        )

        self.assertEqual(
            result["fullHashes"],
            [
                {
                    "fullHash": (
                        base64.b64encode(
                            PHISHING_HASH
                        ).decode("ascii")
                    ),
                    "fullHashDetails": [
                        {
                            "threatType": (
                                "MALWARE"
                            ),
                            "attributes": [
                                "CANARY",
                                "FRAME_ONLY",
                            ],
                        }
                    ],
                }
            ],
        )

    def test_unpacked_attributes_and_multiple_threats(self):
        first = encode_field(1, 2)

        second = (
            encode_field(1, 3)
            + encode_field(2, 1)
            + encode_field(2, 2)
        )

        full_hash = (
            encode_field(1, PHISHING_HASH)
            + encode_field(2, first)
            + encode_field(2, second)
        )

        result = decode_search_hashes_response(
            encode_field(1, full_hash)
        )

        details = result["fullHashes"][0][
            "fullHashDetails"
        ]

        self.assertEqual(
            details,
            [
                {
                    "threatType": (
                        "SOCIAL_ENGINEERING"
                    ),
                    "attributes": [],
                },
                {
                    "threatType": (
                        "UNWANTED_SOFTWARE"
                    ),
                    "attributes": [
                        "CANARY",
                        "FRAME_ONLY",
                    ],
                },
            ],
        )

    def test_unknown_enums_become_invalid_names(self):
        detail = (
            encode_field(1, 9)
            + encode_field(2, 7)
        )

        full_hash = (
            encode_field(1, PHISHING_HASH)
            + encode_field(2, detail)
        )

        result = decode_search_hashes_response(
            encode_field(1, full_hash)
        )

        decoded = result["fullHashes"][0][
            "fullHashDetails"
        ][0]

        self.assertEqual(
            decoded["threatType"],
            "UNKNOWN_THREAT_TYPE_9",
        )

        self.assertEqual(
            decoded["attributes"],
            ["UNKNOWN_THREAT_ATTRIBUTE_7"],
        )

    def test_unknown_fields_are_skipped(self):
        body = (
            encode_field(2, duration(5))
            + encode_field(3, 7)
            + encode_field(4, b"AB")
        )

        self.assertEqual(
            decode_search_hashes_response(
                body
            ),
            {
                "fullHashes": [],
                "cacheDuration": "5s",
            },
        )

    def test_truncated_reply_raises(self):
        full_hash = encode_field(
            1,
            PHISHING_HASH,
        )

        body = encode_field(1, full_hash)

        with self.assertRaises(
            ProtobufDecodeError
        ):
            decode_search_hashes_response(
                body[:-3]
            )

    def test_html_reply_raises(self):
        with self.assertRaises(
            ProtobufDecodeError
        ):
            decode_search_hashes_response(
                b"<html>oops</html>"
            )

    def test_non_bytes_raises(self):
        with self.assertRaises(
            ProtobufDecodeError
        ):
            decode_search_hashes_response(
                "not bytes"
            )

    def test_decode_error_is_a_value_error(self):
        self.assertTrue(
            issubclass(
                ProtobufDecodeError,
                ValueError,
            )
        )

    def test_fractional_durations(self):
        self.assertEqual(
            format_duration(3, 500000000),
            "3.500s",
        )

        self.assertEqual(
            format_duration(1, 1000),
            "1.000001s",
        )

        self.assertEqual(
            format_duration(0, 1),
            "0.000000001s",
        )

    def test_json_error_message(self):
        body = (
            b'{"error": {"code": 400, '
            b'"message": "API key not valid."}}'
        )

        self.assertEqual(
            describe_error_body(
                body,
                "application/json",
            ),
            "API key not valid.",
        )

    def test_protobuf_status_error_message(self):
        body = (
            encode_field(1, 3)
            + encode_field(
                2,
                b"Unsupported Output Format",
            )
        )

        self.assertEqual(
            describe_error_body(
                body,
                "application/x-protobuf",
            ),
            "Unsupported Output Format",
        )

    def test_text_error_message(self):
        self.assertEqual(
            describe_error_body(
                b"Not Found",
                "text/html",
            ),
            "Not Found",
        )

    def test_unreadable_error_body_is_none(self):
        self.assertIsNone(
            describe_error_body(
                b"",
                "",
            )
        )

        self.assertIsNone(
            describe_error_body(
                b"\xff\xff\xff",
                "application/octet-stream",
            )
        )


if __name__ == "__main__":
    unittest.main()
