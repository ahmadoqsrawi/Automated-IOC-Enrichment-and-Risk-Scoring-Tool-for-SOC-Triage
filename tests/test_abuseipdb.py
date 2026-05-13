from dataclasses import replace
from unittest.mock import patch
import pytest
from src.enrichers.base import EnrichmentResult
from src.enrichers.abuseipdb import enrich_abuseipdb
from src.enrichers.http_client import RateLimitError, ApiError


MOCK_RESPONSE = {
    "data": {
        "abuseConfidenceScore": 87,
        "countryCode": "RU",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "HostSailor",
        "domain": "hostsailor.com",
        "totalReports": 143,
        "lastReportedAt": "2024-01-15T10:22:00+00:00",
    }
}


def _make_result(ioc="1.2.3.4") -> EnrichmentResult:
    return EnrichmentResult(ioc=ioc, ioc_type="ip")


class TestEnrichAbuseipdb:
    def test_populates_abuse_score(self):
        with patch("src.enrichers.abuseipdb.get_json", return_value=MOCK_RESPONSE):
            result = enrich_abuseipdb(_make_result(), api_key="fakekey")
        assert result.abuse_score == 87

    def test_populates_abuse_total_reports(self):
        with patch("src.enrichers.abuseipdb.get_json", return_value=MOCK_RESPONSE):
            result = enrich_abuseipdb(_make_result(), api_key="fakekey")
        assert result.abuse_total_reports == 143

    def test_populates_abuse_country(self):
        with patch("src.enrichers.abuseipdb.get_json", return_value=MOCK_RESPONSE):
            result = enrich_abuseipdb(_make_result(), api_key="fakekey")
        assert result.abuse_country == "RU"

    def test_populates_abuse_isp(self):
        with patch("src.enrichers.abuseipdb.get_json", return_value=MOCK_RESPONSE):
            result = enrich_abuseipdb(_make_result(), api_key="fakekey")
        assert result.abuse_isp == "HostSailor"

    def test_populates_country_field(self):
        with patch("src.enrichers.abuseipdb.get_json", return_value=MOCK_RESPONSE):
            result = enrich_abuseipdb(_make_result(), api_key="fakekey")
        assert result.country == "RU"

    def test_original_result_is_not_mutated(self):
        original = _make_result()
        with patch("src.enrichers.abuseipdb.get_json", return_value=MOCK_RESPONSE):
            enriched = enrich_abuseipdb(original, api_key="fakekey")
        assert original.abuse_score == 0
        assert enriched.abuse_score == 87

    def test_raises_rate_limit_error(self):
        with patch("src.enrichers.abuseipdb.get_json", side_effect=RateLimitError("rate limited")):
            with pytest.raises(RateLimitError):
                enrich_abuseipdb(_make_result(), api_key="fakekey")

    def test_raises_api_error(self):
        with patch("src.enrichers.abuseipdb.get_json", side_effect=ApiError("HTTP 401")):
            with pytest.raises(ApiError):
                enrich_abuseipdb(_make_result(), api_key="fakekey")

    def test_raises_value_error_for_non_ip(self):
        result = EnrichmentResult(ioc="example.com", ioc_type="domain")
        with pytest.raises(ValueError, match="AbuseIPDB only supports IP addresses"):
            enrich_abuseipdb(result, api_key="fakekey")

    def test_raises_value_error_for_empty_api_key(self):
        with pytest.raises(ValueError, match="api_key"):
            enrich_abuseipdb(_make_result(), api_key="")
