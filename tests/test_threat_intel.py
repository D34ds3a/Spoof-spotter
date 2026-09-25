import tempfile
import unittest
from pathlib import Path

from core.threat_intel import (
    load_historical_iocs,
    is_historical_ioc,
    find_historical_ioc_sources,
    load_fbi_labhost_csv,
    get_historical_ioc_details,
)


class TestThreatIntel(unittest.TestCase):

    def test_load_historical_iocs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "iocs.txt"

            file_path.write_text(
                "# Source: Test\n"
                "bad-example.com\n"
                "evil-example.net\n",
                encoding="utf-8",
            )

            iocs = load_historical_iocs(file_path)

            self.assertIn("bad-example.com", iocs)
            self.assertIn("evil-example.net", iocs)
            self.assertNotIn("# source: test", iocs)

    def test_historical_ioc_match(self):
        iocs = {
            "bad-example.com",
            "evil-example.net",
        }

        self.assertTrue(
            is_historical_ioc(
                "bad-example.com",
                iocs
            )
        )

    def test_historical_ioc_no_match(self):
        iocs = {
            "bad-example.com",
            "evil-example.net",
        }

        self.assertFalse(
            is_historical_ioc(
                "microsoft.com",
                iocs
            )
        )

    def test_historical_ioc_source_match(self):
        sources = {
            "Test FBI Source": {"bad-example.com",},
            "Test CISA Source": {"different-example.net",},
        }

        matches = find_historical_ioc_sources(
            "bad-example.com",
            sources
        )

        self.assertEqual(
            matches,
            ["Test FBI Source"]
        )

    def test_no_historical_ioc_source_match(self):
        sources = {
            "Test FBI Source": {"bad-example.com",
            }
        }

        matches = find_historical_ioc_sources(
            "microsoft.com",
            sources
        )

        self.assertEqual(matches, [])

    def test_load_fbi_csv(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "labhost.csv"

            file_path.write_text(
                "Domain,Create Date\n"
                "bad-example.com,11/9/2021\n",
                encoding="utf-8",
            )

            records = load_fbi_labhost_csv(file_path)

            self.assertIn(
                "bad-example.com",
                records
            )

            self.assertEqual(
                records["bad-example.com"]["creation_date"],
                "11/9/2021"
            )

    def test_historical_ioc_details(self):
        sources = {
            "Test FBI Source": {
                "bad-example.com": {
                    "creation_date": "11/9/2021",
                    "status": "historical",
                }
            }
        }

        details = get_historical_ioc_details(
            "bad-example.com",
            sources
        )

        self.assertEqual(
            details[0]["source"],
            "Test FBI Source"
        )

        self.assertEqual(
            details[0]["creation_date"],
            "11/9/2021"
        )

if __name__ == "__main__":
    unittest.main()