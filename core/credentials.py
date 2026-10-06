import os

import keyring

from keyring.errors import (
    KeyringError,
    PasswordDeleteError,
)


KEYRING_SERVICE = "Spoof Spotter"


CREDENTIALS = {
    "threatfox": {
        "environment": "THREATFOX_AUTH_KEY",
        "username": "threatfox_api_key",
    },

    "google_safe_browsing": {
        "environment": (
            "GOOGLE_SAFE_BROWSING_API_KEY"
        ),
        "username": (
            "google_safe_browsing_api_key"
        ),
    },

    "virustotal": {
        "environment": "VIRUSTOTAL_API_KEY",
        "username": "virustotal_api_key",
    },
}


def _get_configuration(name):
    configuration = CREDENTIALS.get(
        name
    )

    if configuration is None:
        raise ValueError(
            f"Unknown credential: {name}"
        )

    return configuration


def get_credential(name):
    configuration = (
        _get_configuration(name)
    )

    environment_name = (
        configuration["environment"]
    )

    environment_value = os.getenv(
        environment_name,
        "",
    ).strip()

    if environment_value:
        return environment_value

    try:
        value = keyring.get_password(
            KEYRING_SERVICE,
            configuration["username"],
        )

    except KeyringError:
        return ""

    return (value or "").strip()


def set_credential(name, value):
    configuration = (
        _get_configuration(name)
    )

    value = str(value).strip()

    if not value:
        raise ValueError(
            "Credential cannot be empty."
        )

    keyring.set_password(
        KEYRING_SERVICE,
        configuration["username"],
        value,
    )


def delete_credential(name):
    configuration = (
        _get_configuration(name)
    )

    try:
        keyring.delete_password(
            KEYRING_SERVICE,
            configuration["username"],
        )

    except PasswordDeleteError:
        return False

    except KeyringError:
        return False

    return True


def get_credential_source(name):
    configuration = (
        _get_configuration(name)
    )

    environment_value = os.getenv(
        configuration["environment"],
        "",
    ).strip()

    if environment_value:
        return "environment"

    try:
        value = keyring.get_password(
            KEYRING_SERVICE,
            configuration["username"],
        )

    except KeyringError:
        return "unavailable"

    if value:
        return "keyring"

    return "missing"