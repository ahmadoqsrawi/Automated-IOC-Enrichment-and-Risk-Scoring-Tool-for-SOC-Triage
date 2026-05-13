import pytest
from src.ioc_parser import detect_ioc_type, normalize_ioc


class TestDetectIocType:
    def test_ipv4(self):
        assert detect_ioc_type("8.8.8.8") == "ip"

    def test_ipv6(self):
        assert detect_ioc_type("2001:4860:4860::8888") == "ip"

    def test_url_http(self):
        assert detect_ioc_type("http://example.com/path") == "url"

    def test_url_https(self):
        assert detect_ioc_type("https://example.com/login.php") == "url"

    def test_md5(self):
        assert detect_ioc_type("44d88612fea8a8f36de82e1278abb02f") == "hash"

    def test_sha1(self):
        assert detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash"

    def test_sha256(self):
        assert detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "hash"

    def test_domain(self):
        assert detect_ioc_type("example.com") == "domain"

    def test_subdomain(self):
        assert detect_ioc_type("mail.evil.ru") == "domain"


class TestNormalizeIoc:
    def test_strips_whitespace(self):
        assert normalize_ioc("  8.8.8.8  ") == "8.8.8.8"

    def test_lowercases(self):
        assert normalize_ioc("EXAMPLE.COM") == "example.com"

    def test_strips_trailing_slash_from_domain(self):
        assert normalize_ioc("example.com/") == "example.com"
