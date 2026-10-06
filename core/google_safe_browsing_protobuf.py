"""
Decode Google Safe Browsing v5 replies.

Google's v5 API always answers in protobuf (a compact binary format),
never JSON. This module turns the binary hashes.search reply into the
same dictionary shape Google documents as its "JSON representation":

    {
        "fullHashes": [
            {
                "fullHash": "<base64 of 32 bytes>",
                "fullHashDetails": [
                    {"threatType": "SOCIAL_ENGINEERING", "attributes": []}
                ],
            }
        ],
        "cacheDuration": "300s",
    }

That lets google_safe_browsing_client.py keep all of its existing
validation, matching and caching logic unchanged.

Only the Python standard library is used. Field numbers come from
google/security/safebrowsing/v5/safebrowsing.proto.
"""

import base64
import json


THREAT_TYPE_NAMES = {
    0: "THREAT_TYPE_UNSPECIFIED",
    1: "MALWARE",
    2: "SOCIAL_ENGINEERING",
    3: "UNWANTED_SOFTWARE",
    4: "POTENTIALLY_HARMFUL_APPLICATION",
}

THREAT_ATTRIBUTE_NAMES = {
    0: "THREAT_ATTRIBUTE_UNSPECIFIED",
    1: "CANARY",
    2: "FRAME_ONLY",
}

WIRE_VARINT = 0
WIRE_FIXED64 = 1
WIRE_LENGTH_DELIMITED = 2
WIRE_FIXED32 = 5

MAX_ERROR_MESSAGE_LENGTH = 300


class ProtobufDecodeError(ValueError):
    """Raised when bytes are not a valid protobuf message."""


def _read_varint(data, position):
    result = 0
    shift = 0

    while True:
        if position >= len(data):
            raise ProtobufDecodeError("truncated varint")

        byte = data[position]
        position += 1

        result |= (byte & 0x7F) << shift

        if not byte & 0x80:
            return result, position

        shift += 7

        if shift >= 70:
            raise ProtobufDecodeError("varint too long")


def _to_signed_64(value):
    if value >= (1 << 63):
        return value - (1 << 64)

    return value


def _read_fixed(data, position, size):
    end = position + size

    if end > len(data):
        raise ProtobufDecodeError("truncated fixed-size field")

    return data[position:end], end


def iter_fields(data):
    """Yield (field_number, wire_type, value) for each field in data."""
    position = 0

    while position < len(data):
        key, position = _read_varint(data, position)

        field_number = key >> 3
        wire_type = key & 0x07

        if field_number == 0:
            raise ProtobufDecodeError("invalid field number 0")

        if wire_type == WIRE_VARINT:
            value, position = _read_varint(data, position)

        elif wire_type == WIRE_FIXED64:
            value, position = _read_fixed(data, position, 8)

        elif wire_type == WIRE_LENGTH_DELIMITED:
            length, position = _read_varint(data, position)
            value, position = _read_fixed(data, position, length)

        elif wire_type == WIRE_FIXED32:
            value, position = _read_fixed(data, position, 4)

        else:
            raise ProtobufDecodeError(
                "unsupported wire type %d" % wire_type
            )

        yield field_number, wire_type, value


def format_duration(seconds, nanos):
    """Format a Duration like Google's JSON does: "300s", "3.500s"."""
    negative = seconds < 0 or nanos < 0

    seconds = abs(seconds)
    nanos = abs(nanos)

    if nanos == 0:
        text = "%d" % seconds
    elif nanos % 1000000 == 0:
        text = "%d.%03d" % (seconds, nanos // 1000000)
    elif nanos % 1000 == 0:
        text = "%d.%06d" % (seconds, nanos // 1000)
    else:
        text = "%d.%09d" % (seconds, nanos)

    if negative:
        text = "-" + text

    return text + "s"


def _decode_duration(data):
    seconds = 0
    nanos = 0

    for number, wire_type, value in iter_fields(data):
        if number == 1 and wire_type == WIRE_VARINT:
            seconds = _to_signed_64(value)
        elif number == 2 and wire_type == WIRE_VARINT:
            nanos = _to_signed_64(value)

    return format_duration(seconds, nanos)


def _enum_name(names, value, unknown_prefix):
    return names.get(value, "%s_%d" % (unknown_prefix, value))


def _decode_full_hash_detail(data):
    threat_type = 0
    attributes = []

    for number, wire_type, value in iter_fields(data):
        if number == 1 and wire_type == WIRE_VARINT:
            threat_type = value

        elif number == 2 and wire_type == WIRE_VARINT:
            attributes.append(value)

        elif number == 2 and wire_type == WIRE_LENGTH_DELIMITED:
            position = 0

            while position < len(value):
                item, position = _read_varint(value, position)
                attributes.append(item)

    return {
        "threatType": _enum_name(
            THREAT_TYPE_NAMES,
            threat_type,
            "UNKNOWN_THREAT_TYPE",
        ),
        "attributes": [
            _enum_name(
                THREAT_ATTRIBUTE_NAMES,
                attribute,
                "UNKNOWN_THREAT_ATTRIBUTE",
            )
            for attribute in attributes
        ],
    }


def _decode_full_hash(data):
    full_hash = b""
    details = []

    for number, wire_type, value in iter_fields(data):
        if number == 1 and wire_type == WIRE_LENGTH_DELIMITED:
            full_hash = bytes(value)

        elif number == 2 and wire_type == WIRE_LENGTH_DELIMITED:
            details.append(_decode_full_hash_detail(value))

    return {
        "fullHash": base64.b64encode(full_hash).decode("ascii"),
        "fullHashDetails": details,
    }


def decode_search_hashes_response(data):
    """
    Decode a binary SearchHashesResponse into a dictionary.

    Raises ProtobufDecodeError if the bytes are not valid protobuf.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ProtobufDecodeError("response body must be bytes")

    result = {
        "fullHashes": [],
    }

    for number, wire_type, value in iter_fields(bytes(data)):
        if number == 1 and wire_type == WIRE_LENGTH_DELIMITED:
            result["fullHashes"].append(_decode_full_hash(value))

        elif number == 2 and wire_type == WIRE_LENGTH_DELIMITED:
            result["cacheDuration"] = _decode_duration(value)

    return result


def describe_error_body(body, content_type=""):
    """
    Pull a readable message out of an error reply, or return None.

    Google may send errors as JSON, plain text, or a binary
    google.rpc.Status message. The raw body is never returned.
    """
    if not body:
        return None

    content_type = (content_type or "").lower()

    if "json" in content_type or body[:1] in (b"{", b"["):
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            parsed = None

        if isinstance(parsed, dict):
            error = parsed.get("error", parsed)

            if isinstance(error, dict) and error.get("message"):
                return str(error["message"])[:MAX_ERROR_MESSAGE_LENGTH]

    if content_type.startswith("text/"):
        text = body.decode("utf-8", "replace").strip()
        return text[:MAX_ERROR_MESSAGE_LENGTH] or None

    try:
        for number, wire_type, value in iter_fields(bytes(body)):
            if number == 2 and wire_type == WIRE_LENGTH_DELIMITED:
                message = bytes(value).decode("utf-8", "replace")
                return message[:MAX_ERROR_MESSAGE_LENGTH] or None
    except ProtobufDecodeError:
        pass

    return None
