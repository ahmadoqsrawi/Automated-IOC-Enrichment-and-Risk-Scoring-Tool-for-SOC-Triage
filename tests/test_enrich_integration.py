import logging
from unittest.mock import patch

import pytest

from enrich import process_iocs
from src.enrichers.http_client import RateLimitError


MOCK_ABUSEIPDB_RESPONSE = {
    "data": {
        "abuseConfidenceScore": 95,
        "countryCode": "CN",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "ChinaNet",
        "domain": "chinanet.cn",
        "totalReports": 300,
        "lastReportedAt": "2024-01-15T10:22:00+00:00",
    }
}


class TestProcessIocsWithRealEnricher:
    def test_ip_uses_abuseipdb_when_key_present(self, tmp_path):
        csv = tmp_path / "iocs.csv"
        csv.write_text("ioc,type\n1.2.3.4,ip\n")

        with patch("enrich.ABUSEIPDB_API_KEY", "fakekey"), \
             patch("src.enrichers.abuseipdb.get_json", return_value=MOCK_ABUSEIPDB_RESPONSE):
            records = process_iocs(str(csv))

        assert len(records) == 1
        assert records[0]["abuse_score"] == 95
        assert records[0]["country"] == "CN"

    def test_domain_still_uses_mock_when_key_present(self, tmp_path):
        csv = tmp_path / "iocs.csv"
        csv.write_text("ioc,type\nexample.com,domain\n")

        with patch("enrich.ABUSEIPDB_API_KEY", "fakekey"):
            records = process_iocs(str(csv))

        assert len(records) == 1
        assert records[0]["type"] == "domain"

    def test_ip_uses_mock_when_no_key(self, tmp_path):
        csv = tmp_path / "iocs.csv"
        csv.write_text("ioc,type\n8.8.8.8,ip\n")

        with patch("enrich.ABUSEIPDB_API_KEY", None):
            records = process_iocs(str(csv))

        assert len(records) == 1
        assert records[0]["ioc"] == "8.8.8.8"


class TestProcessIocsWithVirusTotal:
    def test_vt_enrichment_called_when_key_set(self, monkeypatch, tmp_path):
        """VirusTotal enricher is called when VT_API_KEY is set."""
        import enrich as enrich_mod
        monkeypatch.setattr(enrich_mod, "VT_API_KEY", "fake-vt-key")
        monkeypatch.setattr(enrich_mod, "ABUSEIPDB_API_KEY", "fake-abuse-key")
        csv_file = tmp_path / "iocs.csv"
        csv_file.write_text("ioc\n8.8.8.8\n")
        with patch("src.enrichers.virustotal.get_json") as mock_vt:
            mock_vt.return_value = {
                "data": {"attributes": {
                    "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 50},
                    "reputation": -5,
                    "tags": ["scanner"],
                }}
            }
            with patch("src.enrichers.abuseipdb.get_json") as mock_abuse:
                mock_abuse.return_value = {"data": {"abuseConfidenceScore": 0, "totalReports": 0, "countryCode": "US", "isp": "Google"}}
                results = enrich_mod.process_iocs(str(csv_file))
        assert results[0]["vt_malicious"] == 2
        assert results[0]["vt_suspicious"] == 1

    def test_vt_skipped_when_no_key(self, monkeypatch, tmp_path):
        """VirusTotal enricher is skipped when VT_API_KEY is not set."""
        import enrich as enrich_mod
        monkeypatch.setattr(enrich_mod, "VT_API_KEY", None)
        monkeypatch.setattr(enrich_mod, "ABUSEIPDB_API_KEY", "fake-abuse-key")
        csv_file = tmp_path / "iocs.csv"
        csv_file.write_text("ioc\n8.8.8.8\n")
        with patch("src.enrichers.virustotal.get_json") as mock_vt:
            with patch("src.enrichers.abuseipdb.get_json") as mock_abuse:
                mock_abuse.return_value = {"data": {"abuseConfidenceScore": 0, "totalReports": 0, "countryCode": "US", "isp": "Google"}}
                results = enrich_mod.process_iocs(str(csv_file))
        mock_vt.assert_not_called()
        assert results[0]["vt_malicious"] == 0

    def test_vt_rate_limit_falls_back_to_mock(self, monkeypatch, tmp_path, caplog):
        """VirusTotal rate limit error falls back gracefully without crashing."""
        import enrich as enrich_mod
        monkeypatch.setattr(enrich_mod, "VT_API_KEY", "fake-vt-key")
        monkeypatch.setattr(enrich_mod, "ABUSEIPDB_API_KEY", "fake-abuse-key")
        csv_file = tmp_path / "iocs.csv"
        csv_file.write_text("ioc\n8.8.8.8\n")
        with patch("src.enrichers.virustotal.get_json", side_effect=RateLimitError("rate limit")):
            with patch("src.enrichers.abuseipdb.get_json") as mock_abuse:
                mock_abuse.return_value = {"data": {"abuseConfidenceScore": 0, "totalReports": 0, "countryCode": "US", "isp": "Google"}}
                with caplog.at_level(logging.WARNING, logger="src.enrich"):
                    results = enrich_mod.process_iocs(str(csv_file))
        assert any("rate limit" in m.lower() for m in caplog.messages)
        assert results[0]["vt_malicious"] == 0
