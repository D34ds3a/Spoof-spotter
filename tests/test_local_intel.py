import json
import tempfile
import unittest

from datetime import (
    datetime,
    timedelta,
    timezone,
)
from pathlib import Path

from unittest.mock import (
    Mock,
    patch,
)

import requests

from core.local_intel import (
    build_store,
    candidate_hosts,
    check_freshness,
    download_recent_iocs,
    fingerprint,
    load_store,
    lookup,
    normalize_domain,
    normalize_url,
    save_store,
    update_local_intel,
)

from core.threatfox import (
    THREATFOX_API_URL,
)


NOW = datetime(2026, 10, 3, 22, 0, 0, tzinfo=timezone.utc)

# Reserved example names only. No real IOCs are used in tests.
SAMPLE_IOCS = [
    {
        "id": "1001",
        "ioc": "bad-login.example",
        "ioc_type": "domain",
        "threat_type": "payload_delivery",
        "threat_type_desc": "Indicator that identifies a malware distribution server",
        "malware": "win.example_loader",
        "malware_printable": "ExampleLoader",
        "confidence_level": 75,
        "first_seen": "2026-10-01 08:00:00 UTC",
        "last_seen": None,
    },
    {
        "id": "1002",
        "ioc": "evil.dyn.example",
        "ioc_type": "domain",
        "threat_type": "botnet_cc",
        "threat_type_desc": "Indicator that identifies a botnet command&control server",
        "malware_printable": "ExampleBot",
        "confidence_level": 100,
        "first_seen": "2026-10-02 09:00:00 UTC",
        "last_seen": "2026-10-03 07:00:00 UTC",
    },
    {
        "id": "1003",
        "ioc": "HTTP://Files.Example.NET:80/drop/payload.exe?x=1",
        "ioc_type": "url",
        "threat_type": "payload_delivery",
        "malware_printable": "ExampleStealer",
        "confidence_level": 50,
        "first_seen": "2026-10-02 10:00:00 UTC",
    },
    {
        "id": "1004",
        "ioc": "192.0.2.10:443",
        "ioc_type": "ip:port",
        "threat_type": "botnet_cc",
    },
    {
        "id": "1005",
        "ioc": "0" * 64,
        "ioc_type": "sha256_hash",
        "threat_type": "payload",
    },
]


def fake_response(status_code, payload=None):
    response = Mock()
    response.status_code = status_code

    if payload is None:
        response.json.side_effect = ValueError("no JSON")
    else:
        response.json.return_value = payload

    return response


def sample_store(downloaded_at=NOW):
    return build_store(SAMPLE_IOCS, downloaded_at)


class TestNormalizing(unittest.TestCase):

    def test_normalize_domain(self):
        self.assertEqual(
            normalize_domain(" Bad-Login.Example. "),
            "bad-login.example",
        )

        self.assertEqual(
            normalize_domain("Bücher.example"),
            "xn--bcher-kva.example",
        )

        self.assertEqual(normalize_domain(None), "")

    def test_normalize_url(self):
        self.assertEqual(
            normalize_url(
                "HTTP://Files.Example.NET:80/drop/payload.exe?x=1#part"
            ),
            "http://files.example.net/drop/payload.exe?x=1",
        )

        self.assertEqual(
            normalize_url("https://example.com"),
            "https://example.com/",
        )

        self.assertEqual(
            normalize_url("https://example.com:8443/a"),
            "https://example.com:8443/a",
        )

    def test_normalize_url_rejects_other_schemes(self):
        self.assertEqual(normalize_url("ftp://example.com/a"), "")
        self.assertEqual(normalize_url("example.com/a"), "")
        self.assertEqual(normalize_url("https://example.com:99999/"), "")

    def test_fingerprint_separates_types(self):
        self.assertNotEqual(
            fingerprint("domain", "example.com"),
            fingerprint("url", "example.com"),
        )

        self.assertEqual(
            len(fingerprint("domain", "example.com")),
            64,
        )

    def test_candidate_hosts_walk_down_to_base_domain(self):
        self.assertEqual(
            candidate_hosts("a.b.example.co.uk", "example.co.uk"),
            [
                ("a.b.example.co.uk", "subdomain"),
                ("b.example.co.uk", "subdomain"),
                ("example.co.uk", "base_domain"),
            ],
        )

    def test_candidate_hosts_bare_domain(self):
        self.assertEqual(
            candidate_hosts("example.com", "example.com"),
            [("example.com", "base_domain")],
        )


class TestBuildStore(unittest.TestCase):

    def test_store_counts_and_skips(self):
        store = sample_store()

        self.assertEqual(store["domain_count"], 2)
        self.assertEqual(store["url_count"], 1)
        self.assertEqual(store["skipped_count"], 2)
        self.assertEqual(store["downloaded_at"], "2026-10-03T22:00:00Z")

    def test_store_never_contains_readable_iocs(self):
        text = json.dumps(sample_store()).lower()

        for readable in (
            "bad-login",
            "evil.dyn",
            "files.example.net",
            "payload.exe",
            "192.0.2.10",
            '"1001"',
        ):
            self.assertNotIn(readable, text)

    def test_duplicate_keeps_highest_confidence(self):
        iocs = [
            {"ioc": "dup.example", "ioc_type": "domain", "confidence_level": 50},
            {"ioc": "DUP.example", "ioc_type": "domain", "confidence_level": 90},
            {"ioc": "dup.example.", "ioc_type": "domain", "confidence_level": 10},
        ]

        store = build_store(iocs, NOW)

        self.assertEqual(store["domain_count"], 1)

        details = list(store["entries"]["domain"].values())[0]

        self.assertEqual(details["confidence"], 90)

    def test_bad_rows_are_skipped(self):
        store = build_store(
            ["not a dict", {"ioc_type": "domain", "ioc": ""}, {}],
            NOW,
        )

        self.assertEqual(store["domain_count"], 0)
        self.assertEqual(store["skipped_count"], 3)


class TestSaveAndLoad(unittest.TestCase):

    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "local_intel" / "list.json"

            save_store(sample_store(), path)

            store, status = load_store(path)

            self.assertEqual(status, "ok")
            self.assertEqual(store["url_count"], 1)
            self.assertFalse(
                path.with_name(path.name + ".tmp").exists()
            )

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as folder:
            store, status = load_store(Path(folder) / "none.json")

        self.assertIsNone(store)
        self.assertEqual(status, "not_downloaded")

    def test_corrupt_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "list.json"
            path.write_text("{not json", encoding="utf-8")

            store, status = load_store(path)

        self.assertIsNone(store)
        self.assertEqual(status, "invalid_file")

    def test_wrong_structure(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "list.json"

            path.write_text(
                json.dumps({"format_version": 1, "entries": []}),
                encoding="utf-8",
            )

            store, status = load_store(path)

        self.assertEqual(status, "invalid_file")


class TestFreshness(unittest.TestCase):

    def test_fresh(self):
        freshness, age = check_freshness(NOW - timedelta(hours=3), NOW)

        self.assertEqual(freshness, "fresh")
        self.assertAlmostEqual(age, 3)

    def test_stale_after_24_hours(self):
        freshness, _ = check_freshness(NOW - timedelta(hours=24), NOW)

        self.assertEqual(freshness, "stale")

    def test_expired_after_7_days(self):
        freshness, _ = check_freshness(NOW - timedelta(days=7), NOW)

        self.assertEqual(freshness, "expired")

    def test_future_download_time_not_trusted(self):
        freshness, age = check_freshness(NOW + timedelta(hours=2), NOW)

        self.assertEqual(freshness, "invalid_timestamp")
        self.assertIsNone(age)

    def test_small_clock_difference_allowed(self):
        freshness, _ = check_freshness(NOW + timedelta(minutes=2), NOW)

        self.assertEqual(freshness, "fresh")


class TestLookup(unittest.TestCase):

    def test_base_domain_match(self):
        result = lookup(
            "www.bad-login.example",
            "bad-login.example",
            store=sample_store(),
            now=NOW,
        )

        self.assertTrue(result["available"])
        self.assertTrue(result["matched"])
        self.assertEqual(result["freshness"], "fresh")

        match = result["matches"][0]

        self.assertEqual(match["matched_on"], "base_domain")
        self.assertEqual(match["malware"], "ExampleLoader")
        self.assertEqual(match["confidence"], 75)

    def test_subdomain_match_without_flagging_parent(self):
        store = sample_store()

        child = lookup(
            "login.evil.dyn.example",
            "dyn.example",
            store=store,
            now=NOW,
        )

        self.assertTrue(child["matched"])
        self.assertEqual(child["matches"][0]["matched_on"], "subdomain")

        # The shared parent domain is not flagged by itself.
        parent = lookup("dyn.example", "dyn.example", store=store, now=NOW)

        self.assertFalse(parent["matched"])

    def test_url_match_ignores_case_port_and_fragment(self):
        result = lookup(
            "files.example.net",
            "example.net",
            url="http://FILES.example.net/drop/payload.exe?x=1#top",
            store=sample_store(),
            now=NOW,
        )

        self.assertTrue(result["matched"])
        self.assertEqual(result["matches"][0]["matched_on"], "url")

    def test_url_ioc_does_not_flag_whole_host(self):
        result = lookup(
            "files.example.net",
            "example.net",
            url="http://files.example.net/other-page",
            store=sample_store(),
            now=NOW,
        )

        self.assertFalse(result["matched"])

    def test_no_match(self):
        result = lookup(
            "example.com",
            "example.com",
            store=sample_store(),
            now=NOW,
        )

        self.assertTrue(result["available"])
        self.assertFalse(result["matched"])
        self.assertEqual(result["entry_count"], 3)

    def test_stale_list_still_used(self):
        result = lookup(
            "bad-login.example",
            "bad-login.example",
            store=sample_store(NOW - timedelta(hours=30)),
            now=NOW,
        )

        self.assertTrue(result["available"])
        self.assertTrue(result["matched"])
        self.assertEqual(result["freshness"], "stale")

    def test_expired_list_not_used(self):
        result = lookup(
            "bad-login.example",
            "bad-login.example",
            store=sample_store(NOW - timedelta(days=8)),
            now=NOW,
        )

        self.assertFalse(result["available"])
        self.assertFalse(result["matched"])
        self.assertEqual(result["query_status"], "expired")
        self.assertEqual(result["downloaded_at"], "2026-09-25T22:00:00Z")

    def test_missing_list(self):
        with tempfile.TemporaryDirectory() as folder:
            result = lookup(
                "example.com",
                "example.com",
                path=Path(folder) / "none.json",
                now=NOW,
            )

        self.assertFalse(result["available"])
        self.assertEqual(result["query_status"], "not_downloaded")

    @patch("core.local_intel.requests.post")
    @patch("core.local_intel.requests.get")
    def test_lookup_makes_no_network_request(self, mock_get, mock_post):
        lookup(
            "bad-login.example",
            "bad-login.example",
            store=sample_store(),
            now=NOW,
        )

        mock_get.assert_not_called()
        mock_post.assert_not_called()


class TestDownload(unittest.TestCase):

    @patch("core.local_intel.requests.post")
    def test_request_format(self, mock_post):
        mock_post.return_value = fake_response(
            200,
            {"query_status": "ok", "data": SAMPLE_IOCS},
        )

        result = download_recent_iocs(auth_key="test-key", timeout=9)

        args, kwargs = mock_post.call_args

        self.assertEqual(args[0], THREATFOX_API_URL)

        # The key travels in a header, never in the URL.
        self.assertEqual(kwargs["headers"]["Auth-Key"], "test-key")
        self.assertNotIn("test-key", args[0])

        self.assertEqual(
            kwargs["json"],
            {"query": "get_iocs", "days": 7},
        )

        self.assertEqual(kwargs["timeout"], 9)

        self.assertTrue(result["ok"])
        self.assertEqual(len(result["iocs"]), 5)

    @patch("core.local_intel.requests.post")
    def test_missing_key(self, mock_post):
        result = download_recent_iocs(auth_key="")

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "missing_auth_key")

        mock_post.assert_not_called()

    @patch("core.local_intel.get_credential")
    @patch("core.local_intel.requests.post")
    def test_uses_shared_abusech_key(self, mock_post, mock_credential):
        mock_credential.return_value = "stored-key"

        mock_post.return_value = fake_response(
            200,
            {"query_status": "ok", "data": []},
        )

        download_recent_iocs()

        mock_credential.assert_called_once_with("threatfox")

        self.assertEqual(
            mock_post.call_args[1]["headers"]["Auth-Key"],
            "stored-key",
        )

    @patch("core.local_intel.requests.post")
    def test_rejected_key(self, mock_post):
        mock_post.return_value = fake_response(401)

        result = download_recent_iocs(auth_key="bad-key")

        self.assertEqual(result["status"], "authentication_error")
        self.assertEqual(result["http_status"], 401)

    @patch("core.local_intel.requests.post")
    def test_unknown_key_reply(self, mock_post):
        mock_post.return_value = fake_response(
            200,
            {"query_status": "unknown_auth_key"},
        )

        result = download_recent_iocs(auth_key="bad-key")

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "unknown_auth_key")

    @patch("core.local_intel.requests.post")
    def test_network_error_hides_details(self, mock_post):
        mock_post.side_effect = requests.ConnectionError(
            "details that should not be shown"
        )

        result = download_recent_iocs(auth_key="test-key")

        self.assertEqual(result["status"], "request_error")
        self.assertEqual(result["error_type"], "ConnectionError")
        self.assertNotIn("details", json.dumps(result))

    @patch("core.local_intel.requests.post")
    def test_invalid_json(self, mock_post):
        mock_post.return_value = fake_response(200)

        result = download_recent_iocs(auth_key="test-key")

        self.assertEqual(result["status"], "invalid_json")


class TestUpdate(unittest.TestCase):

    @patch("core.local_intel.requests.post")
    def test_update_saves_fingerprints_only(self, mock_post):
        mock_post.return_value = fake_response(
            200,
            {"query_status": "ok", "data": SAMPLE_IOCS},
        )

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "local_intel" / "list.json"

            summary = update_local_intel(
                auth_key="test-key",
                path=path,
                now=NOW,
            )

            saved_text = path.read_text(encoding="utf-8")

        self.assertTrue(summary["ok"])
        self.assertEqual(summary["domain_count"], 2)
        self.assertEqual(summary["url_count"], 1)
        self.assertEqual(summary["skipped_count"], 2)

        self.assertNotIn("bad-login", saved_text)
        self.assertNotIn("test-key", saved_text)

    @patch("core.local_intel.requests.post")
    def test_empty_download_keeps_existing_list(self, mock_post):
        mock_post.return_value = fake_response(
            200,
            {"query_status": "ok", "data": []},
        )

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "list.json"

            save_store(sample_store(), path)
            before = path.read_text(encoding="utf-8")

            summary = update_local_intel(
                auth_key="test-key",
                path=path,
                now=NOW,
            )

            after = path.read_text(encoding="utf-8")

        self.assertFalse(summary["ok"])
        self.assertEqual(summary["status"], "empty_download")
        self.assertEqual(before, after)

    @patch("core.local_intel.requests.post")
    def test_failed_download_writes_nothing(self, mock_post):
        mock_post.return_value = fake_response(503)

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "list.json"

            summary = update_local_intel(
                auth_key="test-key",
                path=path,
                now=NOW,
            )

            self.assertFalse(path.exists())

        self.assertEqual(summary["status"], "http_error")
        self.assertEqual(summary["http_status"], 503)


if __name__ == "__main__":
    unittest.main()
