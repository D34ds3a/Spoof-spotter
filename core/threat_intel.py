import csv
from pathlib import Path


DATA_DIR = Path(__file__).resolve().parent.parent / "data"

HISTORICAL_IOC_DIR = DATA_DIR / "historical_iocs"

FBI_LABHOST_FILE = (HISTORICAL_IOC_DIR / "LabHost_Domains.csv")


def load_fbi_labhost_csv(file_path=FBI_LABHOST_FILE):
    records = {}

    with open(
        file_path,
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:
            domain = (row.get("Domain") or "").strip().lower()
            domain = domain.split("/", 1)[0].rstrip(".")
            create_date = (row.get("Create Date") or "").strip()

            if not domain:
                continue

            records[domain] = {
                "creation_date": create_date,
                "status": "historical",
            }

    return records

def load_historical_iocs(file_path):
    iocs = set()

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            value = line.strip().lower()

            if value and not value.startswith("#"):
                iocs.add(value)

    return iocs


def is_historical_ioc(base_domain, historical_iocs):
    return base_domain.lower() in historical_iocs


def load_historical_sources():
    return {"FBI LabHost FLASH": load_fbi_labhost_csv()}


def candidate_domains(base_domain, hostname=None):
    base_domain = (base_domain or "").strip().lower().rstrip(".")
    hostname = (hostname or "").strip().lower().rstrip(".")

    candidates = []

    if hostname and base_domain and hostname.endswith("." + base_domain):
        labels = hostname.split(".")
        base_label_count = len(base_domain.split("."))

        for start in range(len(labels) - base_label_count):
            candidates.append(".".join(labels[start:]))

    if base_domain:
        candidates.append(base_domain)

    return candidates


def first_matching_domain(records, candidates):
    for candidate in candidates:
        if candidate in records:
            return candidate

    return None


def find_historical_ioc_sources(
    base_domain,
    historical_sources,
    hostname=None,
):
    matches = []

    candidates = candidate_domains(base_domain, hostname)

    for source_name, records in historical_sources.items():
        if first_matching_domain(records, candidates):
            matches.append(source_name)

    return matches


def get_historical_ioc_details(
    base_domain,
    historical_sources,
    hostname=None,
):
    findings = []

    candidates = candidate_domains(base_domain, hostname)

    for source_name, records in historical_sources.items():
        matched_domain = first_matching_domain(records, candidates)

        if matched_domain:
            record = records[matched_domain]

            findings.append(
                {
                    "source": source_name,
                    "domain": matched_domain,
                    "creation_date": record.get(
                        "creation_date",
                        ""
                    ),
                    "status": record.get(
                        "status",
                        "historical"
                    ),
                }
            )

    return findings