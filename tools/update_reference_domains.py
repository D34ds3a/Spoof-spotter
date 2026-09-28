from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from core.tranco_importer import (
    load_tranco_domains,
    write_reference_domains,
)


TRANCO_SOURCE = (
    PROJECT_ROOT
    / "data"
    / "tranco_temp"
    / "top-1m.csv"
)

REFERENCE_OUTPUT = (
    PROJECT_ROOT
    / "data"
    / "reference_domains.txt"
)

REFERENCE_LIMIT = 10000


def main():
    domains = load_tranco_domains(
        TRANCO_SOURCE,
        limit=REFERENCE_LIMIT,
    )

    if not domains:
        print("Error: No Tranco domains were loaded.")
        return

    write_reference_domains(
        domains,
        REFERENCE_OUTPUT,
    )

    print(
        f"Wrote {len(domains):,} reference domains."
    )

    print(
        f"Output: {REFERENCE_OUTPUT}"
    )


if __name__ == "__main__":
    main()