from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from core.google_safe_browsing import (
    build_hash_candidates,
    canonicalize_url,
)

from core.google_safe_browsing_cache import (
    SafeBrowsingCache,
)

from core.google_safe_browsing_client import (
    search_hash_candidates,
)


TEST_URL = (
    "https://testsafebrowsing.appspot.com/"
    "s/phishing.html"
)


def print_result(label, result):
    print()
    print("=" * 55)
    print(label)
    print("=" * 55)

    print(
        "Available:",
        result["available"],
    )

    print(
        "Matched:",
        result["matched"],
    )

    print(
        "Status:",
        result["query_status"],
    )

    print(
        "Network request made:",
        result["network_request_made"],
    )

    print(
        "Cache status:",
        result["cache_status"],
    )

    print(
        "Cache duration:",
        result["cache_duration"],
    )

    if not result["matches"]:
        print("Threat matches: None")
        return

    print(
        "Threat matches:",
        len(result["matches"]),
    )

    for match in result["matches"]:
        print()

        for detail in match["details"]:
            print(
                "Threat type:",
                detail["threatType"],
            )

            print(
                "Attributes:",
                detail["attributes"],
            )


def main():
    print(
        "Google Safe Browsing controlled live test"
    )

    print(
        "The test URL will NOT be visited."
    )

    canonical_url = canonicalize_url(
        TEST_URL
    )

    candidates = build_hash_candidates(
        canonical_url
    )

    print()
    print(
        "Canonical URL:",
        canonical_url,
    )

    print(
        "Hash candidates:",
        len(candidates),
    )

    cache = SafeBrowsingCache()

    first_result = search_hash_candidates(
        candidates,
        cache=cache,
    )

    print_result(
        "FIRST LOOKUP",
        first_result,
    )

    second_result = search_hash_candidates(
        candidates,
        cache=cache,
    )

    print_result(
        "SECOND LOOKUP",
        second_result,
    )


if __name__ == "__main__":
    main()