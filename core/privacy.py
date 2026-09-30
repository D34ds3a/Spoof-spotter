import ipaddress

STANDARD_MODE = "standard"
PRIVACY_MODE = "privacy"

VALID_MODES = {
    STANDARD_MODE,
    PRIVACY_MODE,
}

def normalize_mode(mode):
    mode = str(mode).strip().lower()

    if mode not in VALID_MODES:
        return STANDARD_MODE

    return mode

def is_ip_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_private_or_reserved_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False

    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def is_internal_hostname(hostname):
    hostname = hostname.strip().lower().rstrip(".")

    if not hostname:
        return True

    if hostname == "localhost":
        return True

    if "." not in hostname and not is_ip_address(hostname):
        return True

    return False


def allow_external_lookup(hostname):
    hostname = hostname.strip().lower().rstrip(".")

    if not hostname:
        return False

    if is_ip_address(hostname):
        return False

    if is_internal_hostname(hostname):
        return False

    return True


def service_allowed(service_name, mode=STANDARD_MODE):
    service_name = service_name.strip().lower()
    mode = normalize_mode(mode)

    if service_name == "local":
        return True

    if service_name == "google_safe_browsing":
        return True

    if mode == PRIVACY_MODE:
        return service_name in {
            "privacy_safe_phishing",
        }

    if mode == STANDARD_MODE:
        return service_name in {
            "threatfox",
            "phishtank",
            "privacy_safe_phishing",
        }

def get_mode_policy(mode=STANDARD_MODE):
    mode = normalize_mode(mode)

    if mode == PRIVACY_MODE:
        return {
            "mode": PRIVACY_MODE,
            "local_intelligence": True,
            "threatfox_live": False,
            "google_safe_browsing": True,
            "live_phishing": False,
            "privacy_safe_phishing": True,
        }

    return {
        "mode": STANDARD_MODE,
        "local_intelligence": True,
        "threatfox_live": True,
        "google_safe_browsing": True,
        "live_phishing": True,
        "privacy_safe_phishing": True,
    }

    if mode == STANDARD_MODE:
        return service_name in {
           "threatfox",
            "phishtank",
            "privacy_safe_phishing",
        }

        return False