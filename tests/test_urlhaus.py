import pytest
from unittest.mock import patch

from src.enrichers.base import EnrichmentResult
from src.enrichers.urlhaus import enrich_urlhaus
from src.enrichers.http_client import ApiError, RateLimitError


def _make(ioc: str, ioc_type: str) -> EnrichmentResult:
    return EnrichmentResult(ioc=ioc, ioc_type=ioc_type)


class TestEnrichUrlhausUrl:
    def test_online_url_sets_status_and_tags(self):
        result = _make("https://malware.example.com/bad.exe", "url")
        response = {
            "query_status": "is_url",
            "url_status": "online",
            "tags": ["elf", "botnet"],
            "threat": "malware_download",
        }
        with patch("src.enrichers.urlhaus.post_json", return_value=response):
            enriched = enrich_urlhaus(result)
        assert enriched.urlhaus_status == "online"
        assert enriched.urlhaus_threat == "malware_download"
        assert enriched.urlhaus_tags == ["elf", "botnet"]

    def test_offline_url_sets_status_offline(self):
        result = _make("https://old.example.com/payload", "url")
        response = {
            "query_status": "is_url",
            "url_status": "offline",
            "tags": [],
            "threat": "",
        }
        with patch("src.enrichers.urlhaus.post_json", return_value=response):
            enriched = enrich_urlhaus(result)
        assert enriched.urlhaus_status == "offline"

    def test_no_results_url_sets_not_found(self):
        result = _make("https://clean.example.com/", "url")
        response = {"query_status": "no_results"}
        with patch("src.enrichers.urlhaus.post_json", return_value=response):
            enriched = enrich_urlhaus(result)
        assert enriched.urlhaus_status == "not_found"

    def test_url_uses_correct_endpoint_and_body(self):
        result = _make("https://malware.example.com/bad.exe", "url")
        with patch("src.enrichers.urlhaus.post_json", return_value={"query_status": "no_results"}) as mock_post:
            enrich_urlhaus(result)
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert "urlhaus-api.abuse.ch/v1/url/" in call_kwargs[0][0]
        assert call_kwargs[1]["data"]["url"] == "https://malware.example.com/bad.exe"


class TestEnrichUrlhausHost:
    def test_ip_with_urls_returns_online_and_tags(self):
        result = _make("192.168.1.1", "ip")
        response = {
            "query_status": "is_host",
            "urls": [
                {"url_status": "online", "tags": ["ransomware"], "threat": "malware"},
                {"url_status": "offline", "tags": ["dropper"], "threat": ""},
            ],
        }
        with patch("src.enrichers.urlhaus.post_json", return_value=response):
            enriched = enrich_urlhaus(result)
        assert enriched.urlhaus_status == "online"
        assert enriched.urlhaus_threat == "malware"
        assert set(enriched.urlhaus_tags) == {"ransomware", "dropper"}

    def test_domain_no_results_sets_not_found(self):
        result = _make("example.com", "domain")
        response = {"query_status": "no_results"}
        with patch("src.enrichers.urlhaus.post_json", return_value=response):
            enriched = enrich_urlhaus(result)
        assert enriched.urlhaus_status == "not_found"

    def test_host_uses_correct_endpoint_and_body(self):
        result = _make("192.168.1.1", "ip")
        with patch("src.enrichers.urlhaus.post_json", return_value={"query_status": "no_results"}) as mock_post:
            enrich_urlhaus(result)
        call_kwargs = mock_post.call_args
        assert "urlhaus-api.abuse.ch/v1/host/" in call_kwargs[0][0]
        assert call_kwargs[1]["data"]["host"] == "192.168.1.1"


class TestEnrichUrlhausHash:
    def test_sha256_hash_found(self):
        sha256 = "a" * 64
        result = _make(sha256, "hash")
        response = {
            "query_status": "ok",
            "tags": ["trojan"],
            "threat": "trojan",
        }
        with patch("src.enrichers.urlhaus.post_json", return_value=response):
            enriched = enrich_urlhaus(result)
        assert enriched.urlhaus_status == "online"
        assert enriched.urlhaus_threat == "trojan"
        assert enriched.urlhaus_tags == ["trojan"]

    def test_md5_hash_uses_md5_body_key(self):
        md5 = "b" * 32
        result = _make(md5, "hash")
        with patch("src.enrichers.urlhaus.post_json", return_value={"query_status": "no_results"}) as mock_post:
            enrich_urlhaus(result)
        call_kwargs = mock_post.call_args
        assert "urlhaus-api.abuse.ch/v1/payload/" in call_kwargs[0][0]
        assert call_kwargs[1]["data"]["md5_hash"] == md5

    def test_sha256_hash_uses_sha256_body_key(self):
        sha256 = "c" * 64
        result = _make(sha256, "hash")
        with patch("src.enrichers.urlhaus.post_json", return_value={"query_status": "no_results"}) as mock_post:
            enrich_urlhaus(result)
        call_kwargs = mock_post.call_args
        assert call_kwargs[1]["data"]["sha256_hash"] == sha256

    def test_hash_not_found(self):
        result = _make("d" * 64, "hash")
        with patch("src.enrichers.urlhaus.post_json", return_value={"query_status": "no_results"}):
            enriched = enrich_urlhaus(result)
        assert enriched.urlhaus_status == "not_found"


class TestEnrichUrlhausAuth:
    def test_auth_key_included_in_headers_when_provided(self):
        result = _make("https://malware.example.com/x", "url")
        with patch("src.enrichers.urlhaus.post_json", return_value={"query_status": "no_results"}) as mock_post:
            enrich_urlhaus(result, auth_key="my-secret-key")
        call_kwargs = mock_post.call_args
        assert call_kwargs[1]["headers"]["Auth-Key"] == "my-secret-key"

    def test_no_auth_key_omits_auth_header(self):
        result = _make("https://malware.example.com/x", "url")
        with patch("src.enrichers.urlhaus.post_json", return_value={"query_status": "no_results"}) as mock_post:
            enrich_urlhaus(result)
        call_kwargs = mock_post.call_args
        assert "Auth-Key" not in call_kwargs[1]["headers"]


class TestEnrichUrlhausErrorHandling:
    def test_rate_limit_propagates(self):
        result = _make("https://malware.example.com/x", "url")
        with patch("src.enrichers.urlhaus.post_json", side_effect=RateLimitError("rate limit")):
            with pytest.raises(RateLimitError):
                enrich_urlhaus(result)

    def test_api_error_propagates(self):
        result = _make("https://malware.example.com/x", "url")
        with patch("src.enrichers.urlhaus.post_json", side_effect=ApiError("server error")):
            with pytest.raises(ApiError):
                enrich_urlhaus(result)

    def test_result_is_immutable(self):
        original = _make("https://malware.example.com/x", "url")
        with patch("src.enrichers.urlhaus.post_json", return_value={"query_status": "no_results"}):
            enriched = enrich_urlhaus(original)
        assert original.urlhaus_status == "not_found"
        assert enriched is not original
