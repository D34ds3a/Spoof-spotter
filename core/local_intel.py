"""
Local (offline) threat intelligence from ThreatFox.

tools/update_local_intel.py downloads the IOCs that ThreatFox has
published in the last 7 days and saves them to
data/local_intel/threatfox_recent.json. Spoof Spotter then checks
inputs against that file without making any network request, so the
check also works offline and in Privacy Mode.

Safety design:
- Only SHA-256 fingerprints of domains and URLs are saved. The file
  is not a readable list of malicious websites. Spoof Spotter can
  only answer "is THIS input on the list?"
- The downloaded data is never committed to Git (see .gitignore).
  Each user downloads a fresh copy with their own abuse.ch Auth-Key.
- Nothing on the list is ever opened or visited.

Freshness:
- Less than 24 hours old: fresh.
- 24 hours to 7 days old: stale. Still used, with a warning.
- 7 days or older: expired. Not used until it is updated.

Absence from the local list never means an input is safe.
"""

from datetime import (
    datetime,
    timedelta,
    timezone,
)
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import requests

from core.credentials import (
    get_credential,
)

from core.threatfox import (
    THREATFOX_API_URL,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent

LOCAL_INTEL_DIR = PROJECT_ROOT / "data" / "local_intel"

LOCAL_INTEL_FILE = LOCAL_INTEL_DIR / "threatfox_recent.json"

FORMAT_VERSION = 1

SOURCE_NAME = "ThreatFox (abuse.ch)"

RESULT_SOURCE = "Local ThreatFox list"

DOWNLOAD_DAYS = 7

STALE_AFTER_HOURS = 24
EXPIRE_AFTER_HOURS = 7 * 24

CLOCK_TOLERANCE = timedelta(minutes=5)

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

DOMAIN_TYPE = "domain"
URL_TYPE = "url"

STORED_IOC_TYPES = {
    DOMAIN_TYPE,
    URL_TYPE,
}

MATCHED_ON_BASE_DOMAIN = "base_domain"
MATCHED_ON_SUBDOMAIN = "subdomain"
MATCHED_ON_URL = "url"

DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
}


def normalize_domain(value):
    """Lowercase a domain and convert international names to ASCII."""
    domain = str(value or "").strip().lower().rstrip(".")

    if not domain:
        return ""

    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        return domain


def normalize_url(value):
    """
    Put a URL into one standard form so that the same address always
    produces the same fingerprint.

    Returns "" for anything that is not an http or https URL.
    """
    text = str(value or "").strip()

    if not text:
        return ""

    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return ""

    scheme = parts.scheme.lower()

    if scheme not in DEFAULT_PORTS:
        return ""

    host = normalize_domain(parts.hostname)

    if not host:
        return ""

    if ":" in host:
        host = f"[{host}]"

    if port is not None and port != DEFAULT_PORTS[scheme]:
        host = f"{host}:{port}"

    path = parts.path or "/"

    query = f"?{parts.query}" if parts.query else ""

    return f"{scheme}://{host}{path}{query}"


def fingerprint(ioc_type, normalized_value):
    """SHA-256 fingerprint of an already normalized domain or URL."""
    text = f"{ioc_type}:{normalized_value}"

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def candidate_hosts(hostname, base_domain):
    """
    The hostname and each parent domain down to the base domain.

    For login.secure.example.com with base domain example.com this
    gives login.secure.example.com, secure.example.com and
    example.com. Parents above the base domain, such as .com, are
    never checked.
    """
    hostname = normalize_domain(hostname)
    base_domain = normalize_domain(base_domain)

    candidates = []

    if hostname and base_domain and (
        hostname == base_domain
        or hostname.endswith("." + base_domain)
    ):
        labels = hostname.split(".")
        base_label_count = len(base_domain.split("."))

        for start in range(len(labels) - base_label_count + 1):
            host = ".".join(labels[start:])

            if host == base_domain:
                matched_on = MATCHED_ON_BASE_DOMAIN
            else:
                matched_on = MATCHED_ON_SUBDOMAIN

            candidates.append((host, matched_on))

        return candidates

    if hostname:
        candidates.append((hostname, MATCHED_ON_SUBDOMAIN))

    if base_domain and base_domain != hostname:
        candidates.append((base_domain, MATCHED_ON_BASE_DOMAIN))

    return candidates


def utc_now():
    return datetime.now(timezone.utc)


def format_timestamp(moment):
    return moment.astimezone(timezone.utc).strftime(TIMESTAMP_FORMAT)


def parse_timestamp(text):
    try:
        moment = datetime.strptime(str(text), TIMESTAMP_FORMAT)
    except ValueError:
        return None

    return moment.replace(tzinfo=timezone.utc)


def check_freshness(downloaded_at, now=None):
    """
    Returns (freshness, age_hours).

    freshness is "fresh", "stale", "expired" or "invalid_timestamp".
    """
    now = now or utc_now()

    age = now - downloaded_at

    if age < -CLOCK_TOLERANCE:
        return "invalid_timestamp", None

    age_hours = max(age.total_seconds(), 0) / 3600

    if age_hours >= EXPIRE_AFTER_HOURS:
        return "expired", age_hours

    if age_hours >= STALE_AFTER_HOURS:
        return "stale", age_hours

    return "fresh", age_hours


def _confidence(value):
    if isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        return int(value)

    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _entry_details(ioc_type, ioc):
    malware = (
        ioc.get("malware_printable")
        or ioc.get("malware")
        or ""
    )

    return {
        "ioc_type": ioc_type,
        "threat_type": str(ioc.get("threat_type") or ""),
        "threat_description": str(
            ioc.get("threat_type_desc") or ""
        ),
        "malware": str(malware),
        "confidence": _confidence(ioc.get("confidence_level")),
        "first_seen": str(ioc.get("first_seen") or ""),
        "last_seen": str(ioc.get("last_seen") or ""),
    }


def build_store(iocs, downloaded_at):
    """Turn downloaded ThreatFox IOCs into the fingerprint-only format."""
    entries = {
        DOMAIN_TYPE: {},
        URL_TYPE: {},
    }

    skipped_count = 0

    for ioc in iocs:
        if not isinstance(ioc, dict):
            skipped_count += 1
            continue

        ioc_type = str(ioc.get("ioc_type") or "").strip().lower()

        if ioc_type == DOMAIN_TYPE:
            normalized = normalize_domain(ioc.get("ioc"))
        elif ioc_type == URL_TYPE:
            normalized = normalize_url(ioc.get("ioc"))
        else:
            skipped_count += 1
            continue

        if not normalized:
            skipped_count += 1
            continue

        key = fingerprint(ioc_type, normalized)
        details = _entry_details(ioc_type, ioc)

        existing = entries[ioc_type].get(key)

        if existing is not None:
            if (details["confidence"] or 0) <= (
                existing["confidence"] or 0
            ):
                continue

        entries[ioc_type][key] = details

    return {
        "format_version": FORMAT_VERSION,
        "source": SOURCE_NAME,
        "query": "get_iocs",
        "days": DOWNLOAD_DAYS,
        "downloaded_at": format_timestamp(downloaded_at),
        "hash_algorithm": "sha256",
        "domain_count": len(entries[DOMAIN_TYPE]),
        "url_count": len(entries[URL_TYPE]),
        "skipped_count": skipped_count,
        "entries": entries,
    }


def save_store(store, path=LOCAL_INTEL_FILE):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    temporary_path = path.with_name(path.name + ".tmp")

    with open(temporary_path, "w", encoding="utf-8") as file:
        json.dump(store, file, sort_keys=True)

    os.replace(temporary_path, path)


def load_store(path=LOCAL_INTEL_FILE):
    """Returns (store, status). status is "ok", "not_downloaded" or "invalid_file"."""
    path = Path(path)

    if not path.is_file():
        return None, "not_downloaded"

    try:
        with open(path, "r", encoding="utf-8") as file:
            store = json.load(file)
    except (OSError, ValueError):
        return None, "invalid_file"

    if not isinstance(store, dict):
        return None, "invalid_file"

    if store.get("format_version") != FORMAT_VERSION:
        return None, "invalid_file"

    entries = store.get("entries")

    if not isinstance(entries, dict):
        return None, "invalid_file"

    for ioc_type in STORED_IOC_TYPES:
        if not isinstance(entries.get(ioc_type), dict):
            return None, "invalid_file"

    if parse_timestamp(store.get("downloaded_at")) is None:
        return None, "invalid_file"

    return store, "ok"


def _download_result(status, ok=False, iocs=None, **extra):
    result = {
        "ok": ok,
        "status": status,
        "iocs": iocs or [],
    }

    result.update(extra)

    return result


def download_recent_iocs(
    auth_key=None,
    days=DOWNLOAD_DAYS,
    timeout=60,
):
    """
    Download the ThreatFox IOCs from the last `days` days.

    The Auth-Key is sent in a request header, never in the URL, so it
    cannot leak into error messages or logs.
    """
    if auth_key is None:
        auth_key = get_credential("threatfox")

    if not auth_key:
        return _download_result("missing_auth_key")

    try:
        response = requests.post(
            THREATFOX_API_URL,
            headers={
                "Auth-Key": auth_key,
            },
            json={
                "query": "get_iocs",
                "days": days,
            },
            timeout=timeout,
            allow_redirects=False,
        )

    except requests.RequestException as error:
        return _download_result(
            "request_error",
            error_type=type(error).__name__,
        )

    if response.status_code in (401, 403):
        return _download_result(
            "authentication_error",
            http_status=response.status_code,
        )

    if response.status_code != 200:
        return _download_result(
            "http_error",
            http_status=response.status_code,
        )

    try:
        payload = response.json()
    except ValueError:
        return _download_result("invalid_json")

    if not isinstance(payload, dict):
        return _download_result("invalid_response")

    query_status = str(payload.get("query_status") or "unknown")

    if query_status in ("no_result", "no_results"):
        return _download_result(query_status, ok=True)

    if query_status != "ok":
        return _download_result(query_status)

    data = payload.get("data")

    if data is None:
        data = []

    if not isinstance(data, list):
        return _download_result("invalid_response")

    return _download_result("ok", ok=True, iocs=data)


def update_local_intel(
    auth_key=None,
    path=LOCAL_INTEL_FILE,
    now=None,
    timeout=60,
):
    """Download, fingerprint and save the local list. Returns a summary."""
    download = download_recent_iocs(
        auth_key=auth_key,
        timeout=timeout,
    )

    summary = {
        "ok": False,
        "status": download["status"],
        "path": str(path),
    }

    for key in ("http_status", "error_type"):
        if key in download:
            summary[key] = download[key]

    if not download["ok"]:
        return summary

    if not download["iocs"]:
        summary["status"] = "empty_download"
        return summary

    downloaded_at = now or utc_now()

    store = build_store(download["iocs"], downloaded_at)

    if store["domain_count"] + store["url_count"] == 0:
        summary["status"] = "no_usable_entries"
        return summary

    save_store(store, path)

    summary.update(
        {
            "ok": True,
            "status": "ok",
            "downloaded_at": store["downloaded_at"],
            "domain_count": store["domain_count"],
            "url_count": store["url_count"],
            "skipped_count": store["skipped_count"],
        }
    )

    return summary


def _lookup_result(query_status, available=False, **extra):
    result = {
        "available": available,
        "matched": False,
        "source": RESULT_SOURCE,
        "query_status": query_status,
        "freshness": None,
        "downloaded_at": None,
        "age_hours": None,
        "entry_count": 0,
        "matches": [],
    }

    result.update(extra)

    return result


def lookup(
    hostname,
    base_domain,
    url=None,
    path=LOCAL_INTEL_FILE,
    now=None,
    store=None,
):
    """
    Check a hostname (and optionally a full URL) against the local list.

    No network request is made.
    """
    if store is None:
        store, load_status = load_store(path)

        if store is None:
            return _lookup_result(load_status)

    downloaded_at = parse_timestamp(store.get("downloaded_at"))

    if downloaded_at is None:
        return _lookup_result("invalid_file")

    freshness, age_hours = check_freshness(downloaded_at, now)

    entries = store["entries"]

    file_details = {
        "freshness": freshness,
        "downloaded_at": store["downloaded_at"],
        "age_hours": age_hours,
        "entry_count": (
            len(entries[DOMAIN_TYPE]) + len(entries[URL_TYPE])
        ),
    }

    if freshness in ("expired", "invalid_timestamp"):
        return _lookup_result(freshness, **file_details)

    matches = []

    for host, matched_on in candidate_hosts(hostname, base_domain):
        details = entries[DOMAIN_TYPE].get(
            fingerprint(DOMAIN_TYPE, host)
        )

        if details:
            match = dict(details)
            match["matched_on"] = matched_on
            matches.append(match)

    normalized_url = normalize_url(url) if url else ""

    if normalized_url:
        details = entries[URL_TYPE].get(
            fingerprint(URL_TYPE, normalized_url)
        )

        if details:
            match = dict(details)
            match["matched_on"] = MATCHED_ON_URL
            matches.append(match)

    result = _lookup_result(
        "ok",
        available=True,
        matches=matches,
        **file_details,
    )

    result["matched"] = bool(matches)

    return result
