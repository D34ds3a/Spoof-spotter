import requests

from core.credentials import (
    get_credential,
)


THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"

THREATFOX_AUTH_ENV = "THREATFOX_AUTH_KEY"


def get_auth_key():
    return get_credential("threatfox")


def search_ioc(search_term, auth_key=None, timeout=10):
    if not search_term:
        return {
            "available": True,
            "matched": False,
            "source": "ThreatFox",
            "query_status": "empty_search",
            "results": [],
        }

    key = auth_key or get_auth_key()

    if not key:
        return {
            "available": False,
            "matched": False,
            "source": "ThreatFox",
            "query_status": "missing_auth_key",
            "results": [],
        }

    headers = {
        "Auth-Key": key,
    }

    payload = {
        "query": "search_ioc",
        "search_term": search_term,
        "exact_match": True,
    }

    try:
        response = requests.post(
            THREATFOX_API_URL,
            headers=headers,
            json=payload,
            timeout=timeout,
            allow_redirects=False,
        )

    except requests.RequestException as error:
        return {
            "available": False,
            "matched": False,
            "source": "ThreatFox",
            "query_status": "request_error",
            "error_type": type(error).__name__,
            "results": [],
        }

    if response.status_code in (401, 403):
        return {
            "available": False,
            "matched": False,
            "source": "ThreatFox",
            "query_status": "authentication_error",
            "http_status": response.status_code,
            "results": [],
        }

    if response.status_code != 200:
        return {
            "available": False,
            "matched": False,
            "source": "ThreatFox",
            "query_status": "http_error",
            "http_status": response.status_code,
            "results": [],
        }

    try:
        response_data = response.json()

    except ValueError:
        return {
            "available": False,
            "matched": False,
            "source": "ThreatFox",
            "query_status": "invalid_json",
            "results": [],
        }

    if not isinstance(response_data, dict):
        return {
            "available": False,
            "matched": False,
            "source": "ThreatFox",
            "query_status": "invalid_response",
            "results": [],
        }

    query_status = str(
        response_data.get("query_status") or "unknown"
    )

    if query_status not in ("ok", "no_result"):
        return {
            "available": False,
            "matched": False,
            "source": "ThreatFox",
            "query_status": query_status,
            "results": [],
        }

    if query_status == "no_result":
        return {
            "available": True,
            "matched": False,
            "source": "ThreatFox",
            "query_status": query_status,
            "results": [],
        }

    results = response_data.get("data") or []

    if not isinstance(results, list):
        results = []

    valid_results = [
        result
        for result in results
        if isinstance(result, dict)
    ]

    if results and not valid_results:
        return {
            "available": False,
            "matched": False,
            "source": "ThreatFox",
            "query_status": "invalid_response",
            "results": [],
        }

    results = valid_results

    if not results:
        return {
            "available": True,
            "matched": False,
            "source": "ThreatFox",
            "query_status": query_status,
            "results": [],
        }

    findings = []

    for result in results:
        findings.append(
            {
                "ioc": result.get("ioc", ""),
                "ioc_type": result.get("ioc_type", ""),
                "threat_type": result.get(
                    "threat_type",
                    "",
                ),
                "threat_description": result.get(
                    "threat_type_desc",
                    "",
                ),
                "malware": result.get(
                    "malware_printable",
                    result.get("malware", ""),
                ),
                "confidence": result.get(
                    "confidence_level"
                ),
                "first_seen": result.get(
                    "first_seen",
                    "",
                ),
                "last_seen": result.get(
                    "last_seen",
                    "",
                ),
                "reference": result.get(
                    "reference",
                    "",
                ),
                "is_compromised": result.get(
                    "is_compromised"
                ),
            }
        )

    return {
        "available": True,
        "matched": True,
        "source": "ThreatFox",
        "query_status": query_status,
        "results": findings,
    }