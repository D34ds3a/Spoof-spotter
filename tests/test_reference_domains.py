import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.reference_domains import load_reference_domains


class TestReferenceDomains(unittest.TestCase):

    def test_load_reference_domains(self):
        with TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "reference_domains.txt"

            test_file.write_text(
                "microsoft.com\n"
                "google.com\n"
                "github.com\n",
                encoding="utf-8",
            )

            domains = load_reference_domains(test_file)

            self.assertEqual(
                domains,
                [
                    "microsoft.com",
                    "google.com",
                    "github.com",
                ],
            )

    def test_reference_domains_are_cleaned_and_deduplicated(self):
        with TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "reference_domains.txt"

            test_file.write_text(
                "# Legitimate reference domains\n"
                "\n"
                " Microsoft.COM \n"
                "google.com\n"
                "microsoft.com\n"
                "GITHUB.COM\n",
                encoding="utf-8",
            )

            domains = load_reference_domains(test_file)

            self.assertEqual(
                domains,
                [
                    "microsoft.com",
                    "google.com",
                    "github.com",
                ],
            )


    def test_missing_reference_file_returns_empty_list(self):
        with TemporaryDirectory() as temp_dir:
            missing_file = (
                Path(temp_dir)
                / "does_not_exist.txt"
            )

            domains = load_reference_domains(missing_file)

            self.assertEqual(domains, [])


if __name__ == "__main__":
    unittest.main()