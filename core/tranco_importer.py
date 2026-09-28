import csv
from pathlib import Path


def load_tranco_domains(csv_path, limit=10000):
    csv_path = Path(csv_path)

    if not csv_path.exists():
        return []

    domains = []
    seen_domains = set()

    with csv_path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        reader = csv.reader(file)

        for row in reader:
            if len(row) < 2:
                continue

            domain = row[1].strip().lower()

            if not domain:
                continue

            if domain in seen_domains:
                continue

            domains.append(domain)
            seen_domains.add(domain)

            if len(domains) >= limit:
                break

    return domains

def write_reference_domains(domains, output_path):
    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:
        for domain in domains:
            file.write(f"{domain}\n")

    