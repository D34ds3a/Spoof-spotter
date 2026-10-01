"""
VirusTotal URL and domain reputation lookups.

VirusTotal aggregates verdicts from dozens of security vendors,
including vendors that specialize in phishing detection.

A free VirusTotal Community account provides a personal API key.
The free public API allows 4 lookups per minute and 500 per day,
and must not be used in commercial products or services.

This module only reads existing VirusTotal reports. It never submits
a URL for a new scan.
"""

import base64
from datetime import datetime, timezone

import requests

from core.credentials import (
    get_credential,
)


VIRUSTOTAL_API_URL = (
    "https://www.virustotal.com/api/v3"
)

VIRUSTOTAL_GUI_URL = (
    "https://www.virustotal.com/gui"
)

URL_LOOKUP = "url"
DOMAIN_LOOKUP = "domain"

LOOKUP_TYPES = {
    URL_LOOKUP,
    DOMAIN_LOOKUP,
}

STAT_FIELDS = (
    "malicious",
    "suspicious",
    "harmless",
    "undetected",
    "timeout",
)

def get_api_key():
    return get_credential(
        "virustotal"
    )


def url_identifier(url):
    """VirusTotal URL ID: URL-safe Base64 without padding."""
    encoded = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("ascii")

    return encoded.rstrip("=")


def ascii_domain(domain):
    """Convert an international domain to the ASCII form APIs expect."""
    domain = domain.strip().lower().rstrip(".")

    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        return domain


def _result(
    query_status,
    available,
    lookup_type=None,
    **extra
):
    result = {
        "available": available,
        "matched": False,
        "source": "VirusTotal",
        "query_status": query_status,
        "lookup_type": lookup_type,
    }

    result.update(extra)

    return result


def _read_error_message(response):
    try:
        payload = response.json()
    except ValueError:
        return None

    if not isinstance(payload, dict):
        return None

    error = payload.get("error")

    if isinstance(error, dict):
        message = error.get("message")

        if message:
            return str(message)[:300]

    return None


def _format_timestamp(value):
    if not isinstance(value, (int, float)):
        return None

    try:
        moment = datetime.fromtimestamp(
            value,
            tz=timezone.utc,
        )
    except (OverflowError, OSError, ValueError):
        return None

    return moment.strftime(
        "%Y-%m-%d %H:%M UTC"
    )


def _read_stats(attributes):
    raw_stats = attributes.get(
        "last_analysis_stats"
    )

    if not isinstance(raw_stats, dict):
        raw_stats = {}

    stats = {}

    for field in STAT_FIELDS:
        value = raw_stats.get(field, 0)

        if isinstance(value, bool) or not isinstance(value, int):
            value = 0

        stats[field] = max(value, 0)

    return stats


def _vendors_reporting(attributes, wanted_result):
    results = attributes.get(
        "last_analysis_results"
    )

    if not isinstance(results, dict):
        return []

    vendors = []

    for engine, verdict in results.items():
        if not isinstance(verdict, dict):
            continue

        result_text = str(
            verdict.get("result") or ""
        ).strip().lower()

        if result_text == wanted_result:
            vendors.append(
                str(
                    verdict.get("engine_name")
                    or engine
                )
            )

    return sorted(vendors, key=str.lower)


def _report_link(lookup_type, indicator, data):
    if lookup_type == DOMAIN_LOOKUP:
        return f"{VIRUSTOTAL_GUI_URL}/domain/{indicator}"

    object_id = data.get("id")

    if isinstance(object_id, str) and object_id:
        return f"{VIRUSTOTAL_GUI_URL}/url/{object_id}"

    return None


def lookup(
    indicator,
    lookup_type,
    api_key=None,
    timeout=10,
):
    """
    Look up an existing VirusTotal report for a URL or a domain.

    lookup_type is "url" for a full URL, or "domain" for a
    domain or hostname.
    """
    if lookup_type not in LOOKUP_TYPES:
        raise ValueError(
            f"Unknown VirusTotal lookup type: {lookup_type}"
        )

    indicator = (indicator or "").strip()

    if not indicator:
        return _result(
            "empty_indicator",
            True,
            lookup_type,
        )

    if api_key is None:
        api_key = get_api_key()

    if not api_key:
        return _result(
            "missing_api_key",
            False,
            lookup_type,
        )

    if lookup_type == URL_LOOKUP:
        endpoint = (
            f"{VIRUSTOTAL_API_URL}/urls/"
            f"{url_identifier(indicator)}"
        )
    else:
        indicator = ascii_domain(indicator)

        endpoint = (
            f"{VIRUSTOTAL_API_URL}/domains/"
            f"{indicator}"
        )

    try:
        response = requests.get(
            endpoint,
            headers={
                "x-apikey": api_key,
                "Accept": "application/json",
            },
            timeout=timeout,
        )

    except requests.RequestException as error:
        return _result(
            "request_error",
            False,
            lookup_type,
            error_type=type(error).__name__,
        )

    status_code = response.status_code

    if status_code == 404:
        # VirusTotal has no report for this indicator.
        return _result(
            "not_found",
            True,
            lookup_type,
        )

    if status_code == 429:
        return _result(
            "rate_limited",
            False,
            lookup_type,
            http_status=status_code,
        )

    if status_code in (401, 403):
        return _result(
            "authentication_error",
            False,
            lookup_type,
            http_status=status_code,
            error_message=_read_error_message(response),
        )

    if status_code != 200:
        return _result(
            "http_error",
            False,
            lookup_type,
            http_status=status_code,
            error_message=_read_error_message(response),
        )

    try:
        payload = response.json()
    except ValueError:
        return _result(
            "invalid_json",
            False,
            lookup_type,
        )

    data = (
        payload.get("data")
        if isinstance(payload, dict)
        else None
    )

    if not isinstance(data, dict):
        return _result(
            "invalid_response",
            False,
            lookup_type,
        )

    attributes = data.get("attributes")

    if not isinstance(attributes, dict):
        attributes = {}

    stats = _read_stats(attributes)

    phishing_vendors = _vendors_reporting(
        attributes,
        "phishing",
    )

    reputation = attributes.get("reputation")

    if isinstance(reputation, bool) or not isinstance(reputation, int):
        reputation = None

    flagged = (
        stats["malicious"] > 0
        or stats["suspicious"] > 0
    )

    result = _result(
        "ok",
        True,
        lookup_type,
        stats=stats,
        engines_total=sum(stats.values()),
        phishing_vendors=phishing_vendors,
        reputation=reputation,
        last_analysis_date=_format_timestamp(
            attributes.get("last_analysis_date")
        ),
        report_link=_report_link(
            lookup_type,
            indicator,
            data,
        ),
    )

    result["matched"] = flagged

    return result
