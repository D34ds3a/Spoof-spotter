"""
Controlled live test for VirusTotal and URLhaus.

Checks that your stored API keys work by making one lookup to each
service. The test URL is never opened, and keys are never printed.

Run from the project folder:
    py tools\\manual_virustotal_urlhaus_live.py
"""

from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from core.credentials import (
    get_credential_source,
)

from core.virustotal import (
    lookup as virustotal_lookup,
)

from core.urlhaus import (
    lookup as urlhaus_lookup,
)


VIRUSTOTAL_TEST_URL = (
    "https://testsafebrowsing.appspot.com/"
    "s/phishing.html"
)

URLHAUS_TEST_HOST = "example.com"


def print_header(title):
    print()
    print("=" * 55)
    print(title)
    print("=" * 55)


def credential_ready(name, label):
    source = get_credential_source(name)

    print(f"{label} credential source: {source}")

    if source in {"missing", "unavailable"}:
        print(
            f"{label} key is not available. Store it with "
            "py tools\\configure_api_keys.py"
        )
        return False

    return True


def test_virustotal():
    print_header("VIRUSTOTAL")

    if not credential_ready("virustotal", "VirusTotal"):
        return

    print("Test URL:", VIRUSTOTAL_TEST_URL)
    print("(The test URL is not opened.)")

    result = virustotal_lookup(
        VIRUSTOTAL_TEST_URL,
        "url",
    )

    print()
    print("Available:", result.get("available"))
    print("Status:", result.get("query_status"))
    print("Flagged:", result.get("matched"))

    stats = result.get("stats")

    if stats:
        print(
            "Vendors:",
            f"{stats['malicious']} malicious,",
            f"{stats['suspicious']} suspicious,",
            f"{stats['harmless']} harmless,",
            f"{stats['undetected']} undetected",
        )

    vendors = result.get("phishing_vendors") or []

    if vendors:
        print("Reporting phishing:", ", ".join(vendors[:5]))

    if result.get("http_status") is not None:
        print("HTTP status:", result.get("http_status"))

    if result.get("error_message"):
        print("Error:", result.get("error_message"))


def test_urlhaus():
    print_header("URLHAUS")

    if not credential_ready("threatfox", "abuse.ch (URLhaus)"):
        return

    print("Test host:", URLHAUS_TEST_HOST)

    result = urlhaus_lookup(
        URLHAUS_TEST_HOST,
        "domain",
    )

    print()
    print("Available:", result.get("available"))
    print("Status:", result.get("query_status"))
    print("Matched:", result.get("matched"))

    if result.get("http_status") is not None:
        print("HTTP status:", result.get("http_status"))


def main():
    print("VirusTotal and URLhaus controlled live test")

    test_virustotal()
    test_urlhaus()


if __name__ == "__main__":
    main()
