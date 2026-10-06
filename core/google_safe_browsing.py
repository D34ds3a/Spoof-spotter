import posixpath
import base64
import hashlib
import ipaddress
import tldextract

from urllib.parse import (
    quote,
    unquote,
    urlsplit,
    urlunsplit,
)


PSL_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=(),
    fallback_to_snapshot=True,
    include_psl_private_domains=True,
)

HASH_PREFIX_LENGTH = 4


def remove_control_characters(url):
    return (
        url.replace("\t", "")
        .replace("\r", "")
        .replace("\n", "")
    )


def repeated_unquote(value):
    previous_value = None
    current_value = value

    while current_value != previous_value:
        previous_value = current_value
        current_value = unquote(
            current_value,
            errors="replace",
        )

    return current_value


def canonicalize_hostname(hostname):
    if not hostname:
        return ""

    hostname = hostname.strip(".")

    while ".." in hostname:
        hostname = hostname.replace("..", ".")

    hostname = hostname.lower()

    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        pass

    return hostname


def canonicalize_path(path):
    if not path:
        return "/"

    while "//" in path:
        path = path.replace("//", "/")

    normalized = posixpath.normpath(path)

    if not normalized.startswith("/"):
        normalized = "/" + normalized

    if path.endswith("/") and not normalized.endswith("/"):
        normalized += "/"

    return normalized


SAFE_BROWSING_SAFE_ASCII = "".join(
    chr(code)
    for code in range(33, 127)
    if chr(code) not in "#%"
)


def safe_browsing_escape(value):
    return quote(
        value,
        safe=SAFE_BROWSING_SAFE_ASCII,
    )

def canonicalize_url(url):
    if url is None:
        return None

    url = str(url).strip()

    if not url:
        return None

    url = remove_control_characters(url)

    if "://" not in url:
        url = "http://" + url

    url = url.split("#", 1)[0]

    url = repeated_unquote(url)

    parsed = urlsplit(url)

    hostname = canonicalize_hostname(parsed.hostname)

    if not hostname:
        return None

    path = canonicalize_path(parsed.path)

    query = parsed.query

    path = safe_browsing_escape(path)

    if query:
        query = safe_browsing_escape(query)

    canonical = urlunsplit(
        (
            parsed.scheme.lower(),
            hostname,
            path,
            query,
            "",
        )
    )

    return canonical

def is_ip_literal(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False

def get_registrable_domain(hostname):
    if not hostname:
        return ""

    if is_ip_literal(hostname):
        return hostname

    extracted = PSL_EXTRACTOR(hostname)

    registrable_domain = (extracted.top_domain_under_public_suffix)

    if not registrable_domain:
        return hostname

    return registrable_domain

def generate_host_suffixes(hostname):
    hostname = hostname.lower().strip(".")

    if not hostname:
        return []

    if is_ip_literal(hostname):
        return [hostname]

    registrable_domain = get_registrable_domain(hostname)

    host_labels = hostname.split(".")
    registrable_labels = registrable_domain.split(".")

    registrable_start = (
        len(host_labels)
        - len(registrable_labels)
    )

    start_index = max(
        registrable_start - 3,
        0,
    )

    hosts = [hostname]

    for index in range(
        start_index,
        registrable_start + 1,
    ):
        candidate = ".".join(host_labels[index:])

        if candidate not in hosts:
            hosts.append(candidate)

    return hosts[:5]

def generate_path_prefixes(path, query=""):
    if not path:
        path = "/"

    paths = []

    if query:
        paths.append(f"{path}?{query}")

    if path not in paths:
        paths.append(path)

    if "/" not in paths:
        paths.append("/")

    components = [
        component
        for component in path.split("/")
        if component
    ]

    if not path.endswith("/"):
        components = components[:-1]

    for count in range(
        1,
        min(len(components), 3) + 1,
    ):
        prefix = (
            "/"
            + "/".join(
                components[:count]
            )
            + "/"
        )

        if prefix not in paths:
            paths.append(prefix)

    return paths[:6]

def generate_url_expressions(canonical_url):
    parsed = urlsplit(canonical_url)

    hostname = parsed.hostname

    if not hostname:
        return []

    hosts = generate_host_suffixes(hostname)

    paths = generate_path_prefixes(
        parsed.path,
        parsed.query,
    )

    expressions = []

    for host in hosts:
        for path in paths:
            expression = (
                f"{host}{path}"
            )

            if expression not in expressions:
                expressions.append(expression)

    return expressions

def sha256_expression(expression):
    return hashlib.sha256(expression.encode("utf-8")).digest()

def get_hash_prefix(
    expression,
    prefix_length=HASH_PREFIX_LENGTH,
):
    if prefix_length != HASH_PREFIX_LENGTH:
        raise ValueError(
            "Google Safe Browsing v5 "
            "hashes.search currently requires "
            "exactly 4-byte prefixes."
        )

    full_hash = sha256_expression(expression)

    return full_hash[:prefix_length]

def encode_hash_prefix(prefix):
    return base64.b64encode(prefix).decode("ascii")

def build_hash_candidates(canonical_url):
    expressions = generate_url_expressions(
        canonical_url
    )

    candidates = []

    for expression in expressions:
        full_hash = sha256_expression(
            expression
        )

        prefix = full_hash[
            :HASH_PREFIX_LENGTH
        ]

        candidates.append(
            {
                "expression": expression,
                "full_hash": full_hash,
                "prefix": prefix,
                "prefix_b64": encode_hash_prefix(
                    prefix
                ),
            }
        )

    return candidates
