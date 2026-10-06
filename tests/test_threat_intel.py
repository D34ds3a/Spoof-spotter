import tempfile
import unittest
from pathlib import Path

from core.threat_intel import (
    candidate_domains,
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


    def labhost_sources(self):
        return {
            "Test FBI Source": {
                "login.shared-example.com": {
                    "creation_date": "1/2/2024",
                    "status": "historical",
                }
            }
        }

    def test_candidate_domains(self):
        self.assertEqual(
            candidate_domains("example.co.uk", "a.b.example.co.uk"),
            ["a.b.example.co.uk", "b.example.co.uk", "example.co.uk"],
        )

        self.assertEqual(
            candidate_domains("example.com", "example.com"),
            ["example.com"],
        )

    def test_subdomain_entry_matches_its_hostname(self):
        sources = self.labhost_sources()

        details = get_historical_ioc_details(
            "shared-example.com",
            sources,
            hostname="login.shared-example.com",
        )

        self.assertEqual(details[0]["domain"], "login.shared-example.com")

        self.assertEqual(
            find_historical_ioc_sources(
                "shared-example.com",
                sources,
                hostname="www.login.shared-example.com",
            ),
            ["Test FBI Source"],
        )

    def test_subdomain_entry_does_not_flag_the_parent(self):
        sources = self.labhost_sources()

        for hostname in ("shared-example.com", "other.shared-example.com"):
            self.assertEqual(
                find_historical_ioc_sources(
                    "shared-example.com",
                    sources,
                    hostname=hostname,
                ),
                [],
            )

    def test_labhost_rows_with_path_or_trailing_dot_are_normalized(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "labhost.csv"

            file_path.write_text(
                "Domain,Create Date\n"
                "path-example.com/secure,1/2/2024\n"
                "dot-example.com.,1/3/2024\n",
                encoding="utf-8",
            )

            records = load_fbi_labhost_csv(file_path)

        self.assertIn("path-example.com", records)
        self.assertIn("dot-example.com", records)


if __name__ == "__main__":
    unittest.main()