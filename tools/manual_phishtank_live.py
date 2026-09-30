
from pathlib import Path
import sys


PROJECT_ROOT = (
    Path(__file__).resolve().parent.parent
)

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from core.credentials import (
    get_credential_source,
)

from core.phishtank import (
    check_url,
)

from core.credentials import (
    get_credential_source,
)

from core.phishtank import (
    check_url,
)


TEST_URL = "https://example.com/"


def main():
    print(
        "PhishTank controlled live test"
    )

    print(
        "The test URL will NOT be opened."
    )

    print()

    credential_source = (
        get_credential_source(
            "phishtank"
        )
    )

    print(
        "Credential source:",
        credential_source,
    )

    if credential_source in {
        "missing",
        "unavailable",
    }:
        print(
            "PhishTank credential "
            "is not available."
        )
        return

    print(
        "Test URL:",
        TEST_URL,
    )

    print()
    print(
        "Sending controlled "
        "PhishTank lookup..."
    )

    result = check_url(
        TEST_URL
    )

    print()
    print("=" * 55)
    print("PHISHTANK RESULT")
    print("=" * 55)

    print(
        "Available:",
        result.get(
            "available"
        ),
    )

    print(
        "Matched:",
        result.get(
            "matched"
        ),
    )

    print(
        "Listed:",
        result.get(
            "listed"
        ),
    )

    print(
        "Status:",
        result.get(
            "query_status"
        ),
    )

    print(
        "Rate limit:",
        result.get(
            "rate_limit"
        ),
    )

    print(
        "Rate count:",
        result.get(
            "rate_count"
        ),
    )

    print(
        "Rate interval:",
        result.get(
            "rate_interval"
        ),
    )

    finding = result.get(
        "result"
    )

    if finding:
        print()
        print(
            "Verified:",
            finding.get(
                "verified"
            ),
        )

        print(
            "Valid:",
            finding.get(
                "valid"
            ),
        )


if __name__ == "__main__":
    main()