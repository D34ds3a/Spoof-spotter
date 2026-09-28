from pathlib import Path


DEFAULT_REFERENCE_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "reference_domains.txt"
)


def load_reference_domains(path=None):
    if path is None:
        path = DEFAULT_REFERENCE_PATH

    path = Path(path)

    if not path.exists():
        return []

    domains = []
    seen_domains = set()

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            domain = line.strip().lower()

            if not domain:
                continue

            if domain.startswith("#"):
                continue

            if domain in seen_domains:
                continue

            domains.append(domain)
            seen_domains.add(domain)

    return domains