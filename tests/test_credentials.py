import os
import unittest

from unittest.mock import patch

from core.credentials import (
    KEYRING_SERVICE,
    delete_credential,
    get_credential,
    get_credential_source,
    set_credential,
)


class TestCredentials(
    unittest.TestCase
):

    @patch(
        "core.credentials."
        "keyring.get_password"
    )
    @patch.dict(
        os.environ,
        {
            "THREATFOX_AUTH_KEY":
            "environment-key"
        },
        clear=True,
    )
    def test_environment_has_priority(
        self,
        mock_get_password,
    ):
        result = get_credential(
            "threatfox"
        )

        self.assertEqual(
            result,
            "environment-key",
        )

        mock_get_password.assert_not_called()

    @patch(
        "core.credentials."
        "keyring.get_password",
        return_value="vault-key",
    )
    @patch.dict(
        os.environ,
        {},
        clear=True,
    )
    def test_keyring_fallback(
        self,
        mock_get_password,
    ):
        result = get_credential(
            "threatfox"
        )

        self.assertEqual(
            result,
            "vault-key",
        )

    @patch(
        "core.credentials."
        "keyring.set_password"
    )
    def test_store_credential(
        self,
        mock_set_password,
    ):
        set_credential(
            "threatfox",
            "test-key",
        )

        mock_set_password.assert_called_once_with(
            KEYRING_SERVICE,
            "threatfox_api_key",
            "test-key",
        )

    @patch(
        "core.credentials."
        "keyring.delete_password"
    )
    def test_delete_credential(
        self,
        mock_delete_password,
    ):
        self.assertTrue(
            delete_credential(
                "threatfox"
            )
        )

    def test_empty_key_rejected(self):
        with self.assertRaises(
            ValueError
        ):
            set_credential(
                "threatfox",
                "",
            )

    def test_unknown_service_rejected(
        self,
    ):
        with self.assertRaises(
            ValueError
        ):
            get_credential(
                "not-real"
            )

    @patch(
        "core.credentials."
        "keyring.get_password",
        return_value="virustotal-key",
    )
    @patch.dict(
        os.environ,
        {},
        clear=True,
    )
    def test_virustotal_keyring_fallback(
        self,
        mock_get_password,
    ):
        result = get_credential(
            "virustotal"
        )

        self.assertEqual(
            result,
            "virustotal-key",
        )

    @patch(
    "core.credentials."
    "keyring.get_password"
    )
    @patch.dict(
        os.environ,
        {
            "VIRUSTOTAL_API_KEY":
            "environment-virustotal-key"
        },
        clear=True,
    )
    def test_virustotal_environment_priority(
        self,
        mock_get_password,
    ):
        result = get_credential(
            "virustotal"
        )

        self.assertEqual(
            result,
            "environment-virustotal-key",
        )

        mock_get_password.assert_not_called()


if __name__ == "__main__":
    unittest.main()