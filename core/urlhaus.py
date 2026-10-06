"""
URLhaus URL and host lookups.

URLhaus, run by abuse.ch, tracks URLs used to distribute malware.
It uses the same free abuse.ch Auth-Key as ThreatFox, so no extra
account is needed.

URLhaus focuses on malware distribution, not phishing pages. A host
with URLhaus entries may also be a legitimate site that was
compromised.
"""

import requests

from core.credentials import (
    get_credential,
)


URLHAUS_API_URL = (
    "https://urlhaus-api.abuse.ch/v1"
)

URL_LOOKUP = "url"
HOST_LOOKUP = "domain"

LOOKUP_TYPES = {
    URL_LOOKUP,
    HOST_LOOKUP,
}


def get_auth_key():
    return get_credential(
        "threatfox"
    )


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
        "source": "URLhaus",
        "query_status": query_status,
        "lookup_type": lookup_type,
    }

    result.update(extra)

    return result


def _listed_blocklists(payload):
    blacklists = payload.get("blacklists")

    if not isinstance(blacklists, dict):
        return []

    names = {
        "spamhaus_dbl": "Spamhaus DBL",
        "surbl": "SURBL",
    }

    listed = []

    for key, label in names.items():
        value = str(
            blacklists.get(key) or ""
        ).strip().lower()

        if value and value != "not listed":
            listed.append(f"{label} ({value})")

    return listed


def _clean_tags(tags):
    if not isinstance(tags, list):
        return []

    return sorted(
        {
            str(tag)
            for tag in tags
            if tag
        },
        key=str.lower,
    )


def _summarize_url(payload):
    return {
        "url_status": payload.get("url_status") or "unknown",
        "threat": payload.get("threat") or "",
        "tags": _clean_tags(payload.get("tags")),
        "date_added": payload.get("date_added") or "",
        "last_online": payload.get("last_online") or "",
        "reference": payload.get("urlhaus_reference") or "",
        "blocklists": _listed_blocklists(payload),
    }


def _summarize_host(payload):
    urls = payload.get("urls")

    if not isinstance(urls, list):
        urls = []

    urls = [
        entry
        for entry in urls
        if isinstance(entry, dict)
    ]

    try:
        url_count = int(payload.get("url_count") or len(urls))
    except (TypeError, ValueError):
        url_count = len(urls)

    tags = set()
    threats = set()

    for entry in urls:
        tags.update(_clean_tags(entry.get("tags")))

        if entry.get("threat"):
            threats.add(str(entry["threat"]))

    return {
        "url_count": url_count,
        "online_url_count": sum(
            1
            for entry in urls
            if entry.get("url_status") == "online"
        ),
        "first_seen": payload.get("firstseen") or "",
        "threats": sorted(threats),
        "tags": sorted(tags, key=str.lower),
        "reference": payload.get("urlhaus_reference") or "",
        "blocklists": _listed_blocklists(payload),
    }


def lookup(
    indicator,
    lookup_type,
    auth_key=None,
    timeout=10,
):
    """
    Look up a full URL or a host in URLhaus.

    lookup_type is "url" for a full URL, or "domain" for a
    domain or hostname.
    """
    if lookup_type not in LOOKUP_TYPES:
        raise ValueError(
            f"Unknown URLhaus lookup type: {lookup_type}"
        )

    indicator = (indicator or "").strip()

    if not indicator:
        return _result(
            "empty_indicator",
            True,
            lookup_type,
        )

    if auth_key is None:
        auth_key = get_auth_key()

    if not auth_key:
        return _result(
            "missing_auth_key",
            False,
            lookup_type,
        )

    if lookup_type == URL_LOOKUP:
        endpoint = f"{URLHAUS_API_URL}/url/"
        form_data = {"url": indicator}
    else:
        endpoint = f"{URLHAUS_API_URL}/host/"
        form_data = {"host": ascii_domain(indicator)}

    try:
        response = requests.post(
            endpoint,
            data=form_data,
            headers={
                "Auth-Key": auth_key,
            },
            timeout=timeout,
            allow_redirects=False,
        )

    except requests.RequestException as error:
        return _result(
            "request_error",
            False,
            lookup_type,
            error_type=type(error).__name__,
        )

    if response.status_code in (401, 403):
        return _result(
            "authentication_error",
            False,
            lookup_type,
            http_status=response.status_code,
        )

    if response.status_code != 200:
        return _result(
            "http_error",
            False,
            lookup_type,
            http_status=response.status_code,
        )

    try:
        payload = response.json()
    except ValueError:
        return _result(
            "invalid_json",
            False,
            lookup_type,
        )

    if not isinstance(payload, dict):
        return _result(
            "invalid_response",
            False,
            lookup_type,
        )

    query_status = str(
        payload.get("query_status") or "unknown"
    )

    if query_status in (
        "no_results",
        "invalid_url",
        "invalid_host",
    ):
        return _result(
            query_status,
            True,
            lookup_type,
        )

    if query_status != "ok":
        return _result(
            query_status,
            False,
            lookup_type,
        )

    if lookup_type == URL_LOOKUP:
        details = _summarize_url(payload)
    else:
        details = _summarize_host(payload)

    result = _result(
        "ok",
        True,
        lookup_type,
        details=details,
    )

    result["matched"] = True

    return result
