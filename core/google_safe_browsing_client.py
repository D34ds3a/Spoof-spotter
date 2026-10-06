import base64
from core.credentials import (
    get_credential,
)
from decimal import (
    Decimal,
    InvalidOperation,
)

import requests

from core.google_safe_browsing_cache import (
    SafeBrowsingCache,
)

from core.google_safe_browsing_protobuf import (
    decode_search_hashes_response,
    describe_error_body,
)



GOOGLE_HASHES_SEARCH_URL = (
    "https://safebrowsing.googleapis.com"
    "/v5/hashes:search"
)

VALID_THREAT_TYPES = {
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
}

VALID_THREAT_ATTRIBUTES = {
    "CANARY",
    "FRAME_ONLY",
}

NON_ENFORCEABLE_ATTRIBUTES = {
    "CANARY",
    "FRAME_ONLY",
}


DEFAULT_CACHE = SafeBrowsingCache()


def get_api_key():
    return get_credential("google_safe_browsing")


class GoogleSafeBrowsingHttpError(Exception):
    """Google answered, but with an HTTP error status."""

    def __init__(
        self,
        status_code,
        message=None,
    ):
        self.status_code = status_code

        self.message = message or (
            "Google Safe Browsing "
            "returned an HTTP error."
        )

        super().__init__(
            self.message
        )


def request_full_hashes(
    hash_prefixes,
    api_key,
    timeout=10,
):
    """
    Ask Google for full hashes matching
    the 4-byte prefixes.

    Only the Base64 prefixes are sent.
    The key goes in a header (not the URL)
    so it never lands in logs or history.

    Returns the decoded reply as a dict.

    Raises GoogleSafeBrowsingHttpError for
    HTTP errors, requests.RequestException
    for network problems, and ValueError
    (ProtobufDecodeError) for a bad reply.
    """
    response = requests.get(
        GOOGLE_HASHES_SEARCH_URL,
        params={
            "hashPrefixes": list(
                hash_prefixes
            ),
        },
        headers={
            "x-goog-api-key": api_key,
        },
        timeout=timeout,
        allow_redirects=False,
    )

    if response.status_code != 200:
        raise GoogleSafeBrowsingHttpError(
            response.status_code,
            describe_error_body(
                response.content,
                response.headers.get(
                    "Content-Type",
                    "",
                ),
            ),
        )

    return decode_search_hashes_response(
        response.content
    )


def parse_cache_duration(value):
    if not isinstance(value, str):
        return 0.0

    value = value.strip()

    if not value.endswith("s"):
        return 0.0

    try:
        seconds = Decimal(
            value[:-1]
        )
    except InvalidOperation:
        return 0.0

    if not seconds.is_finite():
        return 0.0

    if seconds <= 0:
        return 0.0

    return float(seconds)


def validate_full_hash_detail(detail):
    if not isinstance(detail, dict):
        return None

    threat_type = detail.get(
        "threatType"
    )

    if threat_type not in VALID_THREAT_TYPES:
        return None

    attributes = detail.get(
        "attributes",
        [],
    )

    if not isinstance(
        attributes,
        list,
    ):
        return None

    for attribute in attributes:
        if (
            attribute
            not in VALID_THREAT_ATTRIBUTES
        ):
            return None

    return {
        "threatType": threat_type,
        "attributes": list(
            attributes
        ),
    }


def validate_full_hash_details(
    details,
):
    if not isinstance(details, list):
        return []

    valid_details = []

    for detail in details:
        validated = (
            validate_full_hash_detail(
                detail
            )
        )

        if validated is not None:
            valid_details.append(
                validated
            )

    return valid_details


def build_search_result(
    candidates,
    returned_hashes,
    cache_status,
    network_request_made,
    cache_duration=None,
):
    candidates_by_hash = {}

    for candidate in candidates:
        full_hash = candidate.get(
            "full_hash"
        )

        if (
            not isinstance(
                full_hash,
                bytes,
            )
            or len(full_hash) != 32
        ):
            continue

        candidates_by_hash.setdefault(
            full_hash,
            [],
        ).append(candidate)

    matches = []
    seen_matches = set()

    for returned_hash in returned_hashes:
        full_hash_b64 = (
            returned_hash.get(
                "fullHash"
            )
        )

        if not full_hash_b64:
            continue

        try:
            full_hash = (
                base64.b64decode(
                    full_hash_b64,
                    validate=True,
                )
            )
        except (
            ValueError,
            TypeError,
        ):
            continue

        if len(full_hash) != 32:
            continue

        local_candidates = (
            candidates_by_hash.get(
                full_hash,
                [],
            )
        )

        details = (
            validate_full_hash_details(
                returned_hash.get(
                    "fullHashDetails",
                    [],
                )
            )
        )

        if not details:
            continue

        for candidate in local_candidates:
            match_key = (
                candidate["expression"],
                full_hash_b64,
            )

            if match_key in seen_matches:
                continue

            seen_matches.add(
                match_key
            )

            matches.append(
                {
                    "expression": (
                        candidate[
                            "expression"
                        ]
                    ),
                    "full_hash_b64": (
                        full_hash_b64
                    ),
                    "details": details,
                }
            )

    return {
        "available": True,
        "matched": bool(matches),
        "query_status": "ok",
        "matches": matches,
        "cache_duration": (
            cache_duration
        ),
        "cache_status": cache_status,
        "network_request_made": (
            network_request_made
        ),
    }


def has_enforceable_match(result):
    if not isinstance(result, dict):
        return False

    for match in result.get("matches") or []:
        if not isinstance(match, dict):
            continue

        for detail in match.get("details") or []:
            if not isinstance(detail, dict):
                continue

            attributes = set(detail.get("attributes") or [])

            if not attributes & NON_ENFORCEABLE_ATTRIBUTES:
                return True

    return False


def search_hash_candidates(
    candidates,
    api_key=None,
    timeout=10,
    cache=None,
):
    if cache is None:
        cache = DEFAULT_CACHE

    if not candidates:
        return {
            "available": True,
            "matched": False,
            "query_status": (
                "empty_candidates"
            ),
            "matches": [],
            "cache_duration": None,
            "cache_status": (
                "not_checked"
            ),
            "network_request_made": (
                False
            ),
        }

    prefixes = []
    seen_prefixes = set()

    for candidate in candidates:
        prefix_b64 = candidate.get(
            "prefix_b64"
        )

        if not prefix_b64:
            continue

        if prefix_b64 in seen_prefixes:
            continue

        prefixes.append(
            prefix_b64
        )

        seen_prefixes.add(
            prefix_b64
        )

    if not prefixes:
        return {
            "available": True,
            "matched": False,
            "query_status": (
                "empty_prefixes"
            ),
            "matches": [],
            "cache_duration": None,
            "cache_status": (
                "not_checked"
            ),
            "network_request_made": (
                False
            ),
        }

    cached_results = {}
    uncached_prefixes = []

    for prefix in prefixes:
        cached = cache.get(
            prefix
        )

        if cached is None:
            uncached_prefixes.append(
                prefix
            )
        else:
            cached_results[
                prefix
            ] = cached

    if not uncached_prefixes:
        returned_hashes = []

        for hashes in (
            cached_results.values()
        ):
            returned_hashes.extend(
                hashes
            )

        return build_search_result(
            candidates,
            returned_hashes,
            cache_status="hit",
            network_request_made=False,
        )

   
    if api_key is None:
        api_key = get_api_key()

    if not api_key:
        return {
            "available": False,
            "matched": False,
            "query_status": (
                "missing_api_key"
            ),
            "matches": [],
            "cache_duration": None,
            "cache_status": (
                "partial"
                if cached_results
                else "miss"
            ),
            "network_request_made": (
                False
            ),
        }

    try:
        payload = request_full_hashes(
            uncached_prefixes,
            api_key,
            timeout=timeout,
        )

    except GoogleSafeBrowsingHttpError as error:
        return {
            "available": False,
            "matched": False,
            "query_status": "http_error",
            "http_status": (
                error.status_code
            ),
            "error_message": (
                error.message
            ),
            "matches": [],
            "cache_duration": None,
            "cache_status": (
                "partial"
                if cached_results
                else "miss"
            ),
            "network_request_made": True,
        }

    except requests.RequestException as error:
     
        return {
            "available": False,
            "matched": False,
            "query_status": (
                "network_error"
            ),
            "error_type": (
                type(error).__name__
            ),
            "matches": [],
            "cache_duration": None,
            "cache_status": (
                "partial"
                if cached_results
                else "miss"
            ),
            "network_request_made": True,
        }

    except ValueError:
     
        return {
            "available": False,
            "matched": False,
            "query_status": (
                "invalid_response"
            ),
            "matches": [],
            "cache_duration": None,
            "cache_status": (
                "partial"
                if cached_results
                else "miss"
            ),
            "network_request_made": True,
        }

    raw_cache_duration = (
        payload.get(
            "cacheDuration"
        )
    )

    cache_duration_seconds = (
        parse_cache_duration(
            raw_cache_duration
        )
    )


    fresh_results = {
        prefix: []
        for prefix in uncached_prefixes
    }

    for returned_hash in payload.get(
        "fullHashes",
        [],
    ):
        if not isinstance(
            returned_hash,
            dict,
        ):
            continue

        full_hash_b64 = (
            returned_hash.get(
                "fullHash"
            )
        )

        if not full_hash_b64:
            continue

        try:
            full_hash = (
                base64.b64decode(
                    full_hash_b64,
                    validate=True,
                )
            )
        except (
            ValueError,
            TypeError,
        ):
            continue

        if len(full_hash) != 32:
            continue

        prefix_b64 = (
            base64.b64encode(
                full_hash[:4]
            ).decode("ascii")
        )

        if (
            prefix_b64
            not in fresh_results
        ):
            continue

        fresh_results[
            prefix_b64
        ].append(
            {
                "fullHash": (
                    full_hash_b64
                ),
                "fullHashDetails": (
                    validate_full_hash_details(
                        returned_hash.get(
                            "fullHashDetails",
                            [],
                        )
                    )
                ),
            }
        )

  
    for (
        prefix,
        full_hashes,
    ) in fresh_results.items():
        cache.set(
            prefix,
            full_hashes,
            cache_duration_seconds,
        )

    all_returned_hashes = []

    for hashes in (
        cached_results.values()
    ):
        all_returned_hashes.extend(
            hashes
        )

    for hashes in (
        fresh_results.values()
    ):
        all_returned_hashes.extend(
            hashes
        )

    if cached_results:
        cache_status = "partial"
    else:
        cache_status = "miss"

    return build_search_result(
        candidates,
        all_returned_hashes,
        cache_status=cache_status,
        network_request_made=True,
        cache_duration=(
            raw_cache_duration
        ),
    )