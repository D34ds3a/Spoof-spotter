from urllib.parse import urlparse

def classify_input(user_input):
    user_input = user_input.strip()

    if not user_input:
        return "empty"

    if "@" in user_input:
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