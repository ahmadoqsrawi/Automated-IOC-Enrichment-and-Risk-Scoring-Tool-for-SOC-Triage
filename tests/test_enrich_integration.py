from unittest.mock import patch

import pytest

from enrich import process_iocs


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
