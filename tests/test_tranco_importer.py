import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.tranco_importer import (
    load_tranco_domains,
    write_reference_domains,
)


class TestTrancoImporter(unittest.TestCase):

    def test_load_tranco_domains_respects_limit(self):
        with TemporaryDirectory() as temp_dir:
            csv_file = Path(temp_dir) / "top-1m.csv"

            csv_file.write_text(
                "1,google.com\n"
                "2,cloudflare.com\n"
                "3,facebook.com\n"
                "4,gstatic.com\n",
                encoding="utf-8",
            )

            domains = load_tranco_domains(
                csv_file,
                limit=3,
            )

            self.assertEqual(
                domains,
                [
                    "google.com",
                    "cloudflare.com",
                    "facebook.com",
                ],
            )

    def test_write_reference_domains(self):
        with TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "reference_domains.txt"

            domains = [
                "google.com",
                "cloudflare.com",
                "facebook.com",
            ]

            write_reference_domains(
                domains,
                output_file,
            )

            contents = output_file.read_text(
                encoding="utf-8"
            )

            self.assertEqual(
                contents,
                "google.com\n"
                "cloudflare.com\n"
                "facebook.com\n",
            )

if __name__ == "__main__":
    unittest.main()