import contextlib
import io
import os
import unittest

from unittest.mock import Mock, patch
from urllib.parse import urlparse

import requests

import spoof_spotter

from core.google_safe_browsing_cache import (
    SafeBrowsingCache,
)


FAKE_KEYS = {
    "THREATFOX_AUTH_KEY": "test-abusech-key",
    "GOOGLE_SAFE_BROWSING_API_KEY": "test-google-key",
    "VIRUSTOTAL_API_KEY": "test-virustotal-key",
}

GOOGLE_HOST = "safebrowsing.googleapis.com"

THREATFOX_HOST = "threatfox-api.abuse.ch"

SECRET_URL = "https://example.net/reset?token=fake-test-token"

ALL_HOSTS = {
    "threatfox-api.abuse.ch",
    "www.virustotal.com",
    "urlhaus-api.abuse.ch",
    GOOGLE_HOST,
}


def local_list_not_downloaded(*args, **kwargs):
    return {
        "available": False,
        "matched": False,
        "source": "Local ThreatFox list",
        "query_status": "not_downloaded",
        "freshness": None,
        "downloaded_at": None,
        "age_hours": None,
        "entry_count": 0,
        "matches": [],
    }


class TestRouting(unittest.TestCase):

    def run_main(self, *answers):
        calls = []

        def recorder(method):
            def fake_request(url, *args, **kwargs):
                calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "json": kwargs.get("json"),
                        "data": kwargs.get("data"),
                    }
                )

                raise requests.ConnectionError("network disabled in tests")

            return fake_request

        replies = iter(answers)
        output = io.StringIO()

        self.local_intel = Mock(side_effect=local_list_not_downloaded)

        with patch.dict(os.environ, FAKE_KEYS), \
                patch("builtins.input", lambda *_: next(replies)), \
                patch("requests.get", recorder("GET")), \
                patch("requests.post", recorder("POST")), \
                patch("core.google_safe_browsing_client.DEFAULT_CACHE", SafeBrowsingCache()), \
                patch("spoof_spotter.local_intel_lookup", self.local_intel), \
                patch("spoof_spotter.load_reference_domains", return_value=["microsoft.com", "example.com"]), \
                patch("spoof_spotter.load_historical_sources", return_value={"FBI LabHost FLASH": {}}), \
                contextlib.redirect_stdout(output):
            spoof_spotter.main()

        return calls, output.getvalue()

    def hosts(self, calls):
        return {urlparse(call["url"]).hostname for call in calls}

    def test_privacy_mode_sends_only_google_hash_prefixes(self):
        calls, output = self.run_main("2", "https://login.example.net/verify")

        self.assertIn("Analysis mode: Privacy", output)
        self.assertEqual(self.hosts(calls), {GOOGLE_HOST})
        self.assertNotIn("example.net", repr(calls))

    def test_privacy_mode_email_sends_only_google_hash_prefixes(self):
        calls, output = self.run_main("2", "alice@login.example.net")

        self.assertEqual(self.hosts(calls), {GOOGLE_HOST})
        self.assertNotIn("example.net", repr(calls))

    def test_standard_mode_uses_every_service(self):
        calls, output = self.run_main("1", "https://login.example.net/verify", "y")

        self.assertIn("Analysis mode: Standard", output)
        self.assertEqual(self.hosts(calls), ALL_HOSTS)

    def test_unrecognized_mode_answer_asks_again(self):
        calls, output = self.run_main("p", "２", "privacy", "login.example.net")

        self.assertEqual(
            output.count("Please enter 1 for Standard or 2 for Privacy."),
            2,
        )
        self.assertIn("Analysis mode: Privacy", output)
        self.assertEqual(self.hosts(calls), {GOOGLE_HOST})

    def test_internal_names_and_ip_addresses_are_never_sent(self):
        for value in (
            "printer.lan",
            "router.home.arpa",
            "http://127.1/",
            "http://10.0.0.5/admin",
            "alice@nas.local",
        ):
            calls, output = self.run_main("1", value)

            self.assertEqual(calls, [], value)
            self.assertIn("External Lookup Blocked", output, value)

    def test_malformed_input_is_rejected_without_crashing(self):
        for value in (
            "http://[1.2.3.4]/",
            "http://[::1",
            "alice@example.net?x=1",
            "alice@example.net:8080",
            "http://",
        ):
            calls, output = self.run_main("1", value)

            self.assertEqual(calls, [], value)
            self.assertIn("Error:", output, value)

    def risk_score(self, output):
        for line in output.splitlines():
            if line.startswith("Risk score:"):
                return line

        return None

    def test_full_url_confirmed_sends_the_url_to_virustotal_and_urlhaus(self):
        for answer in ("y", "Y", "yes", " YES "):
            calls, output = self.run_main("1", SECRET_URL, answer)

            self.assertIn(spoof_spotter.FULL_URL_WARNING, output)
            self.assertEqual(self.hosts(calls), ALL_HOSTS, answer)

            urlhaus_calls = [call for call in calls if "urlhaus" in call["url"]]
            self.assertEqual(urlhaus_calls[0]["data"], {"url": SECRET_URL})

            virustotal_calls = [call for call in calls if "virustotal" in call["url"]]
            self.assertIn("/urls/", virustotal_calls[0]["url"])

    def test_full_url_is_not_sent_unless_confirmed(self):
        for answer in ("", "n", "N", "no", "NO", "maybe", "yess", "1"):
            calls, output = self.run_main("1", SECRET_URL, answer)

            self.assertEqual(self.hosts(calls), {THREATFOX_HOST, GOOGLE_HOST}, answer)
            self.assertNotIn("fake-test-token", repr(calls), answer)
            self.assertNotIn("/reset", repr(calls), answer)

            self.assertIn("VirusTotal status: User Declined", output)
            self.assertIn("URLhaus status: User Declined", output)

            self.assertEqual(
                output.count("Full-URL lookup skipped - user declined URL disclosure."),
                2,
            )

    def test_declining_keeps_local_intelligence_and_threatfox_base_domain_lookup(self):
        calls, output = self.run_main("1", SECRET_URL, "")

        self.local_intel.assert_called_once()
        self.assertEqual(self.local_intel.call_args[1]["url"], SECRET_URL)

        threatfox_calls = [call for call in calls if THREATFOX_HOST in call["url"]]
        self.assertEqual(threatfox_calls[0]["json"]["search_term"], "example.net")

    def test_declining_does_not_change_the_score(self):
        declined_calls, declined = self.run_main("1", SECRET_URL, "n")
        confirmed_calls, confirmed = self.run_main("1", SECRET_URL, "y")

        self.assertIsNotNone(self.risk_score(declined))
        self.assertEqual(self.risk_score(declined), self.risk_score(confirmed))

    def test_warning_does_not_echo_the_url(self):
        calls, output = self.run_main("1", SECRET_URL, "n")

        before_report = output.split("SPOOF SPOTTER REPORT")[0]

        self.assertIn(spoof_spotter.FULL_URL_WARNING, before_report)
        self.assertNotIn("fake-test-token", before_report)

    def test_no_url_prompt_for_bare_domain_or_email(self):
        for value in (
            "login.example.net",
            "example.net/reset?token=fake-test-token",
            "alice@login.example.net",
        ):
            calls, output = self.run_main("1", value)

            self.assertNotIn(spoof_spotter.FULL_URL_WARNING, output, value)
            self.assertEqual(self.hosts(calls), ALL_HOSTS, value)
            self.assertNotIn("fake-test-token", repr(calls), value)

    def test_no_url_prompt_in_privacy_mode(self):
        calls, output = self.run_main("2", SECRET_URL)

        self.assertNotIn(spoof_spotter.FULL_URL_WARNING, output)
        self.assertEqual(self.hosts(calls), {GOOGLE_HOST})
        self.assertIn("VirusTotal status: Privacy Mode", output)

    def test_no_url_prompt_for_internal_urls(self):
        calls, output = self.run_main("1", "http://printer.lan/reset?token=fake-test-token")

        self.assertNotIn(spoof_spotter.FULL_URL_WARNING, output)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
