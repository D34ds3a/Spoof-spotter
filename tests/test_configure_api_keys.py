import contextlib
import io
import unittest

from unittest.mock import patch

from keyring.errors import (
    NoKeyringError,
)

from tools import configure_api_keys


class TestConfigureApiKeys(unittest.TestCase):

    def test_missing_credential_vault_is_reported_without_crashing(self):
        output = io.StringIO()

        with patch("builtins.input", return_value="3"), \
                patch("tools.configure_api_keys.getpass", return_value="test-value-123"), \
                patch("tools.configure_api_keys.set_credential", side_effect=NoKeyringError("no backend")), \
                contextlib.redirect_stdout(output):
            configure_api_keys.store_credential()

        text = output.getvalue()

        self.assertIn("credential vault is not available", text)
        self.assertIn("NoKeyringError", text)
        self.assertNotIn("test-value-123", text)
        self.assertNotIn("stored in the OS credential vault", text)

    def test_remove_with_missing_vault_is_reported(self):
        output = io.StringIO()

        with patch("builtins.input", return_value="3"), \
                patch("tools.configure_api_keys.get_credential_source", return_value="unavailable"), \
                patch("tools.configure_api_keys.delete_credential") as mock_delete, \
                contextlib.redirect_stdout(output):
            configure_api_keys.remove_credential()

        self.assertIn("credential vault is not available", output.getvalue())
        mock_delete.assert_not_called()


if __name__ == "__main__":
    unittest.main()
