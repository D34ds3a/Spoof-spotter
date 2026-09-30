import requests

from core.credentials import (
    get_credential,
)


PHISHTANK_API_URL = (
    "https://checkurl.phishtank.com/"
    "checkurl/"
)

PHISHTANK_USER_AGENT = (
    "SpoofSpotter/1.0"
)


def get_api_key():
    return get_credential(
        "phishtank"
    )


def _to_bool(value):
    if value is True:
        return True

    if value is False:
        return False

    if isinstance(value, str):
        return (
            value.strip().lower()
            in {
                "true",
                "yes",
                "y",
                "1",
            }
        )

    if isinstance(value, int):
        return value != 0

    return False


def _extract_result(payload):
    if not isinstance(payload, dict):
        return None

    results = payload.get(
        "results"
    )

    if not isinstance(results, dict):
        return None

    if "in_database" in results:
        return results

    url_zero = results.get(
        "url0"
    )

    if isinstance(url_zero, dict):
        return url_zero

    return None


def check_url(
    url,
    api_key=None,
    timeout=10,
):
    if not url:
        return {
            "available": True,
            "matched": False,
            "listed": False,
            "source": "PhishTank",
            "query_status": "empty_url",
            "result": None,
        }

    if api_key is None:
        api_key = get_api_key()

    form_data = {
        "url": url,
        "format": "json",
    }

    if api_key:
        form_data["app_key"] = (
            api_key
        )

    headers = {
        "User-Agent": (
            PHISHTANK_USER_AGENT
        ),
        "Accept": (
            "application/json"
        ),
    }

    try:
        response = requests.post(
            PHISHTANK_API_URL,
            data=form_data,
            headers=headers,
            timeout=timeout,
        )

        if response.status_code == 509:
            return {
                "available": False,
                "matched": False,
                "listed": False,
                "source": "PhishTank",
                "query_status": (
                    "rate_limited"
                ),
                "result": None,
            }

        response.raise_for_status()

        payload = response.json()

    except requests.RequestException:
        return {
            "available": False,
            "matched": False,
            "listed": False,
            "source": "PhishTank",
            "query_status": (
                "request_error"
            ),
            "result": None,
        }

    except ValueError:
        return {
            "available": False,
            "matched": False,
            "listed": False,
            "source": "PhishTank",
            "query_status": (
                "invalid_json"
            ),
            "result": None,
        }

    result = _extract_result(
        payload
    )

    if result is None:
        return {
            "available": False,
            "matched": False,
            "listed": False,
            "source": "PhishTank",
            "query_status": (
                "invalid_response"
            ),
            "result": None,
        }

    in_database = _to_bool(
        result.get(
            "in_database"
        )
    )

    verified = _to_bool(
        result.get(
            "verified"
        )
    )

    valid = _to_bool(
        result.get(
            "valid"
        )
    )

    matched = (
        in_database
        and verified
        and valid
    )

    normalized = {
        "url": result.get(
            "url",
            "",
        ),
        "in_database": (
            in_database
        ),
        "phish_id": result.get(
            "phish_id"
        ),
        "phish_detail_page": (
            result.get(
                "phish_detail_page",
                "",
            )
        ),
        "verified": verified,
        "verified_at": result.get(
            "verified_at",
            "",
        ),
        "valid": valid,
        "submitted_at": result.get(
            "submitted_at",
            "",
        ),
    }

    return {
        "available": True,
        "matched": matched,
        "listed": in_database,
        "source": "PhishTank",
        "query_status": "ok",
        "result": normalized,
        "rate_limit": (
            response.headers.get(
                "X-Request-Limit"
            )
        ),
        "rate_count": (
            response.headers.get(
                "X-Request-Count"
            )
        ),
        "rate_interval": (
            response.headers.get(
                "X-Request-Limit-Interval"
            )
        ),
    }