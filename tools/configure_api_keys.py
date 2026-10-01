from getpass import getpass
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
    delete_credential,
    get_credential_source,
    set_credential,
)


SERVICES = {
    "1": (
        "threatfox",
        "ThreatFox / URLhaus",
    ),

    "2": (
        "google_safe_browsing",
        "Google Safe Browsing",
    ),

    "3": (
        "virustotal",
        "VirusTotal",
    ),
}


def show_status():
    print()
    print("Credential status")
    print("-----------------")

    for name, label in (
        SERVICES.values()
    ):
        source = get_credential_source(
            name
        )

        print(
            f"{label}: {source}"
        )


def store_credential():
    print()
    print("1. ThreatFox / URLhaus (abuse.ch Auth-Key)")
    print("2. Google Safe Browsing")
    print("3. VirusTotal")

    choice = input(
        "Select service: "
    ).strip()

    service = SERVICES.get(
        choice
    )

    if service is None:
        print("Invalid selection.")
        return

    name, label = service

    value = getpass(
        f"Enter {label} API key: "
    ).strip()

    if not value:
        print("No key entered.")
        return

    set_credential(
        name,
        value,
    )

    print(
        f"{label} key stored "
        "in the OS credential vault."
    )


def remove_credential():
    print()
    print("1. ThreatFox / URLhaus (abuse.ch Auth-Key)")
    print("2. Google Safe Browsing")
    print("3. VirusTotal")

    choice = input(
        "Select service: "
    ).strip()

    service = SERVICES.get(
        choice
    )

    if service is None:
        print("Invalid selection.")
        return

    name, label = service

    removed = delete_credential(
        name
    )

    if removed:
        print(
            f"{label} key removed."
        )
    else:
        print(
            f"No stored {label} key "
            "was found."
        )


def main():
    while True:
        print()
        print("==============================")
        print(" SPOOF SPOTTER API KEY SETUP")
        print("==============================")
        print("1. Store/update API key")
        print("2. Show credential status")
        print("3. Remove API key")
        print("4. Exit")

        choice = input(
            "Select option: "
        ).strip()

        if choice == "1":
            store_credential()

        elif choice == "2":
            show_status()

        elif choice == "3":
            remove_credential()

        elif choice == "4":
            return

        else:
            print(
                "Invalid selection."
            )


if __name__ == "__main__":
    main()