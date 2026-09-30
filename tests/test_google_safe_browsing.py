import unittest

from core.google_safe_browsing import (
    canonicalize_hostname,
    canonicalize_path,
    canonicalize_url,
    remove_control_characters,
    repeated_unquote,
    build_hash_candidates,
    encode_hash_prefix,
    generate_host_suffixes,
    generate_path_prefixes,
    generate_url_expressions,
    get_hash_prefix,
    sha256_expression,
    safe_browsing_escape,
)


class TestGoogleSafeBrowsing(unittest.TestCase):

    def test_remove_control_characters(self):
        result = remove_control_characters("http://exa\tmple.com/\r\nlogin")

        self.assertEqual(
            result,
            "http://example.com/login",
        )

    def test_repeated_percent_decoding(self):
        result = repeated_unquote("%252Flogin")

        self.assertEqual(
            result,
            "/login",
        )

    def test_hostname_lowercase(self):
        result = canonicalize_hostname(
            "WWW.Example.COM"
        )

        self.assertEqual(
            result,
            "www.example.com",
        )

    def test_hostname_removes_extra_dots(self):
        result = canonicalize_hostname(".www..example.com.")

        self.assertEqual(
            result,
            "www.example.com",
        )

    def test_unicode_hostname_becomes_punycode(self):
        result = canonicalize_hostname("bücher.example")

        self.assertEqual(
            result,
            "xn--bcher-kva.example",
        )

    def test_empty_path_becomes_root(self):
        result = canonicalize_path("")

        self.assertEqual(
            result,
            "/",
        )

    def test_repeated_slashes_collapsed(self):
        result = canonicalize_path("/one//two///three")

        self.assertEqual(
            result,
            "/one/two/three",
        )

    def test_dot_segments_resolved(self):
        result = canonicalize_path("/one/./two/../three")

        self.assertEqual(
            result,
            "/one/three",
        )

    def test_fragment_removed(self):
        result = canonicalize_url("http://example.com/login#section")

        self.assertEqual(
            result,
            "http://example.com/login",
        )

    def test_domain_without_path_gets_slash(self):
        result = canonicalize_url("http://example.com")

        self.assertEqual(
            result,
            "http://example.com/",
        )

    def test_domain_without_scheme_is_supported(self):
        result = canonicalize_url("example.com/login")

        self.assertEqual(
            result,
            "http://example.com/login",
        )

    def test_query_is_preserved(self):
        result = canonicalize_url(
            "https://example.com/login?id=123"
        )

        self.assertEqual(
            result,
            "https://example.com/login?id=123",
        )

    def test_empty_input_returns_none(self):
        self.assertIsNone(canonicalize_url(""))

    def test_generate_simple_host_suffixes(self):
        result = generate_host_suffixes(
            "a.b.com"
        )

        self.assertEqual(
           result,
            [
                "a.b.com",
                "b.com",
            ],
        )


    def test_generate_long_host_suffixes(self):
        result = generate_host_suffixes("a.b.c.d.e.f.com")

        self.assertEqual(
            result,
            [
                "a.b.c.d.e.f.com",
                "c.d.e.f.com",
                "d.e.f.com",
                "e.f.com",
                "f.com",
            ],
         )


    def test_generate_path_prefixes(self):
        result = generate_path_prefixes(
           "/1/2.html",
            "param=1",
        )

        self.assertEqual(
            result,
            [
                "/1/2.html?param=1",
                "/1/2.html",
                "/",
                "/1/",
            ],
        )


    def test_google_documented_expression_example(self):
        result = generate_url_expressions("http://a.b.com/1/2.html?param=1")

        self.assertEqual(
            result,
            [
                "a.b.com/1/2.html?param=1",
                "a.b.com/1/2.html",
                "a.b.com/",
                "a.b.com/1/",
                "b.com/1/2.html?param=1",
                "b.com/1/2.html",
                "b.com/",
                "b.com/1/",
            ],
        )


    def test_sha256_hash_is_32_bytes(self):
        result = sha256_expression("example.com/")

        self.assertEqual(
            len(result),
            32,
        )


    def test_hash_prefix_is_exactly_four_bytes(self):
        result = get_hash_prefix("example.com/")

        self.assertEqual(
            len(result),
            4,
        )


    def test_hash_prefix_matches_start_of_full_hash(self):
        full_hash = sha256_expression("example.com/")

        prefix = get_hash_prefix("example.com/")

        self.assertEqual(
            prefix,
            full_hash[:4],
        )


    def test_known_example_hash_prefix(self):
        prefix = get_hash_prefix("example.com/")

        self.assertEqual(
            prefix.hex(),
            "73d986e0",
        )


    def test_known_example_base64_prefix(self):
        prefix = get_hash_prefix("example.com/")

        encoded = encode_hash_prefix(prefix)

        self.assertEqual(
            encoded,
            "c9mG4A==",
        )


    def test_build_hash_candidates(self):
        candidates = build_hash_candidates("http://example.com/")

        self.assertGreater(
            len(candidates),
            0,
        )

        candidate = candidates[0]

        self.assertIn(
            "expression",
            candidate,
        )

        self.assertEqual(
            len(candidate["full_hash"]),
            32,
        )

        self.assertEqual(
            len(candidate["prefix"]),
            4,
        )

    def test_printable_ascii_is_preserved(self):
        result = safe_browsing_escape("/a;b@c")

        self.assertEqual(
            result,
            "/a;b@c",
        )


    def test_required_characters_are_escaped(self):
        result = safe_browsing_escape("/a b#c%d")

        self.assertEqual(
            result,
            "/a%20b%23c%25d",
        )

    def test_rejects_non_four_byte_prefix(self):
        with self.assertRaises(ValueError):
            get_hash_prefix(
                "example.com/",
                prefix_length=8,
            )


if __name__ == "__main__":
    unittest.main()