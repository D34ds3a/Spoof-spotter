from urllib.parse import urlparse
import tldextract

def classify_input(user_input):
    user_input = user_input.strip()

    if not user_input:
        return "empty"

    if "://" in user_input:
        return "domain"

    if "@" in user_input and "/" not in user_input:
        return "email"

    return "domain"

def parse_email(user_input):
    address, domain = user_input.rsplit("@", 1)

    return address, domain.lower()

def parse_domain(user_input):
    user_input = user_input.strip()

    if "://" not in user_input:
        user_input = "//" + user_input

    parsed_url = urlparse(user_input)

    if parsed_url.hostname:
        return parsed_url.hostname.lower()

    return ""

def extract_domain_parts(user_input):
    hostname = parse_domain(user_input)

    if not hostname:
        return "", ""

    extracted = tldextract.extract(hostname)

    if not extracted.domain or not extracted.suffix:
        return "", ""

    base_domain = f"{extracted.domain}.{extracted.suffix}"
    subdomain = extracted.subdomain

    return subdomain, base_domain


def validate_domain(user_input):
    hostname = parse_domain(user_input)

    if not hostname:
        return False

    if len(hostname) > 253:
        return False

    labels = hostname.split(".")

    if len(labels) < 2:
        return False

    for label in labels:
        if not label:
            return False

        if len(label) > 63:
            return False

        if label.startswith("-") or label.endswith("-"):
            return False

        for character in label:
            if not (character.isalnum() or character == "-"):
                return False

    return True

def validate_email(user_input):
    user_input = user_input.strip()

    if user_input.count("@") != 1:
        return False

    address, domain = user_input.rsplit("@", 1)

    if not address:
        return False

    if ".." in address:
        return False

    if address.startswith("."):
        return False

    if address.endswith("."):
        return False

    if not domain:
        return False

    if " " in address:
        return False

    return validate_domain(domain)