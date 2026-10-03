"""
Download or refresh the local ThreatFox list.

Downloads the IOCs ThreatFox published in the last 7 days and saves
only SHA-256 fingerprints of the domains and URLs. The readable list
is never written to disk, no IOC is opened, and your Auth-Key is
never printed.

Uses the same abuse.ch Auth-Key as ThreatFox and URLhaus.

Run from the project folder:
    py tools\\update_local_intel.py
"""

from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from core.credentials import (
    get_credential_source,
)

from core.local_intel import (
    DOWNLOAD_DAYS,
    EXPIRE_AFTER_HOURS,
    LOCAL_INTEL_FILE,
    STALE_AFTER_HOURS,
    update_local_intel,
)


STATUS_HELP = {
    "missing_auth_key": (
        "No abuse.ch Auth-Key found. Store it with "
        "py tools\\configure_api_keys.py"
    ),
    "authentication_error": (
        "abuse.ch rejected the Auth-Key. Check it with "
        "py tools\\configure_api_keys.py"
    ),
    "unknown_auth_key": (
        "abuse.ch does not recognize the Auth-Key. Check it with "
        "py tools\\configure_api_keys.py"
    ),
    "request_error": (
        "Could not reach ThreatFox. Check your internet "
        "connection and try again."
    ),
    "empty_download": (
        "ThreatFox returned no IOCs, so the existing local list "
        "was kept. Try again later."
    ),
    "no_usable_entries": (
        "The download had no domain or URL IOCs, so the existing "
        "local list was kept. Try again later."
    ),
}


def main():
    print("Spoof Spotter local ThreatFox list update")
    print()

    source = get_credential_source("threatfox")

    print(f"abuse.ch credential source: {source}")
    print(f"Downloading ThreatFox IOCs from the last {DOWNLOAD_DAYS} days...")

    summary = update_local_intel()

    print()

    if not summary["ok"]:
        status = summary["status"]

        print(f"Update failed: {status}")

        if summary.get("http_status") is not None:
            print(f"HTTP status: {summary['http_status']}")

        if summary.get("error_type"):
            print(f"Network error type: {summary['error_type']}")

        help_text = STATUS_HELP.get(status)

        if help_text:
            print(help_text)

        return 1

    print("Update complete.")
    print(f"Domain fingerprints saved: {summary['domain_count']:,}")
    print(f"URL fingerprints saved: {summary['url_count']:,}")
    print(
        f"Other IOC types skipped (IP:port, file hashes): "
        f"{summary['skipped_count']:,}"
    )
    print(f"Downloaded at: {summary['downloaded_at']}")
    print(f"Saved to: {LOCAL_INTEL_FILE}")
    print()
    print(
        f"The list is treated as stale after {STALE_AFTER_HOURS} hours "
        f"and is not used after {EXPIRE_AFTER_HOURS // 24} days."
    )
    print("Only fingerprints were saved. No readable addresses were written.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
