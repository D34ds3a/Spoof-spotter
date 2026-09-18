from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

APPROVED_DOMAINS_FILE = DATA_DIR / "approved_domains.txt"

def load_approved_domains(file_path=APPROVED_DOMAINS_FILE):
    approved_domains = set()

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            domain = line.strip().lower()

            if domain:
                approved_domains.add(domain)

    return approved_domains

def is_approved_domain(base_domain, approved_domains):
    return base_domain.lower() in approved_domains