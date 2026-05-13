import base64
from unittest.mock import patch

import pytest

from src.enrichers.base import EnrichmentResult
from src.enrichers.virustotal import enrich_virustotal
from src.enrichers.http_client import RateLimitError, ApiError


def _vt_response(malicious: int = 5, suspicious: int = 2, harmless: int = 60,
                 reputation: int = -10, tags: list[str] | None = None) -> dict:
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": 5,
                },
                "reputation": reputation,
                "tags": tags or ["trojan", "malware"],
            }
        }
    }


def _make(ioc: str, ioc_type: str) -> EnrichmentResult:
    return EnrichmentResult(ioc=ioc, ioc_type=ioc_type)


class TestEnrichVirustotalIp:
    def test_populates_vt_malicious(self):
        with patch("src.enrichers.virustotal.get_json", return_value=_vt_response(malicious=8)):
            result = enrich_virustotal(_make("1.2.3.4", "ip"), api_key="fakekey")
        assert result.vt_malicious == 8

    def test_populates_vt_suspicious(self):
        with patch("src.enrichers.virustotal.get_json", return_value=_vt_response(suspicious=3)):
            result = enrich_virustotal(_make("1.2.3.4", "ip"), api_key="fakekey")
        assert result.vt_suspicious == 3

    def test_populates_vt_harmless(self):
        with patch("src.enrichers.virustotal.get_json", return_value=_vt_response(harmless=70)):
            result = enrich_virustotal(_make("1.2.3.4", "ip"), api_key="fakekey")
        assert result.vt_harmless == 70

    def test_populates_vt_reputation(self):
        with patch("src.enrichers.virustotal.get_json", return_value=_vt_response(reputation=-5)):
            result = enrich_virustotal(_make("1.2.3.4", "ip"), api_key="fakekey")
        assert result.vt_reputation == -5

    def test_populates_vt_tags(self):
        with patch("src.enrichers.virustotal.get_json", return_value=_vt_response(tags=["trojan"])):
            result = enrich_virustotal(_make("1.2.3.4", "ip"), api_key="fakekey")
        assert result.vt_tags == ["trojan"]

    def test_uses_ip_addresses_endpoint(self):
        with patch("src.enrichers.virustotal.get_json", return_value=_vt_response()) as mock_get:
            enrich_virustotal(_make("1.2.3.4", "ip"), api_key="fakekey")
        called_url = mock_get.call_args[0][0]
        assert "ip_addresses/1.2.3.4" in called_url


class TestEnrichVirustotalDomain:
    def test_uses_domains_endpoint(self):
        with patch("src.enrichers.virustotal.get_json", return_value=_vt_response()) as mock_get:
            enrich_virustotal(_make("evil.com", "domain"), api_key="fakekey")
        called_url = mock_get.call_args[0][0]
        assert "domains/evil.com" in called_url

    def test_populates_fields(self):
        with patch("src.enrichers.virustotal.get_json", return_value=_vt_response(malicious=3)):
            result = enrich_virustotal(_make("evil.com", "domain"), api_key="fakekey")
        assert result.vt_malicious == 3


class TestEnrichVirustotalHash:
    def test_uses_files_endpoint(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        with patch("src.enrichers.virustotal.get_json", return_value=_vt_response()) as mock_get:
            enrich_virustotal(_make(sha256, "hash"), api_key="fakekey")
        called_url = mock_get.call_args[0][0]
        assert f"files/{sha256}" in called_url

    def test_populates_fields(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        with patch("src.enrichers.virustotal.get_json", return_value=_vt_response(malicious=55)):
            result = enrich_virustotal(_make(sha256, "hash"), api_key="fakekey")
        assert result.vt_malicious == 55


class TestEnrichVirustotalUrl:
    def test_uses_urls_endpoint_with_base64_id(self):
        url = "http://evil.com/payload.exe"
        expected_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        with patch("src.enrichers.virustotal.get_json", return_value=_vt_response()) as mock_get:
            enrich_virustotal(_make(url, "url"), api_key="fakekey")
        called_url = mock_get.call_args[0][0]
        assert f"urls/{expected_id}" in called_url

    def test_populates_fields(self):
        with patch("src.enrichers.virustotal.get_json", return_value=_vt_response(malicious=10)):
            result = enrich_virustotal(_make("http://evil.com/payload.exe", "url"), api_key="fakekey")
        assert result.vt_malicious == 10


class TestEnrichVirustotalErrors:
    def test_raises_value_error_for_empty_api_key(self):
        with pytest.raises(ValueError, match="api_key is required"):
            enrich_virustotal(_make("1.2.3.4", "ip"), api_key="")

    def test_raises_value_error_for_unknown_ioc_type(self):
        with pytest.raises(ValueError, match="Unsupported IOC type"):
            enrich_virustotal(_make("something", "unknown"), api_key="fakekey")

    def test_original_result_is_not_mutated(self):
        original = _make("1.2.3.4", "ip")
        with patch("src.enrichers.virustotal.get_json", return_value=_vt_response(malicious=9)):
            enriched = enrich_virustotal(original, api_key="fakekey")
        assert original.vt_malicious == 0
        assert enriched.vt_malicious == 9

    def test_propagates_rate_limit_error(self):
        with patch("src.enrichers.virustotal.get_json", side_effect=RateLimitError("rate limited")):
            with pytest.raises(RateLimitError):
                enrich_virustotal(_make("1.2.3.4", "ip"), api_key="fakekey")

    def test_propagates_api_error(self):
        with patch("src.enrichers.virustotal.get_json", side_effect=ApiError("HTTP 403")):
            with pytest.raises(ApiError):
                enrich_virustotal(_make("1.2.3.4", "ip"), api_key="fakekey")

    def test_missing_attributes_defaults_to_zero(self):
        with patch("src.enrichers.virustotal.get_json", return_value={"data": {"attributes": {}}}):
            result = enrich_virustotal(_make("1.2.3.4", "ip"), api_key="fakekey")
        assert result.vt_malicious == 0
        assert result.vt_tags == []
