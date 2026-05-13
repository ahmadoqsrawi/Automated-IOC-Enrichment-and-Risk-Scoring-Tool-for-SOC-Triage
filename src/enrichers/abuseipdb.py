import logging
from dataclasses import replace

from src.enrichers.base import EnrichmentResult
from src.enrichers.http_client import get_json

_log = logging.getLogger(__name__)
_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def enrich_abuseipdb(result: EnrichmentResult, api_key: str) -> EnrichmentResult:
    """Enrich an IP-type IOC with AbuseIPDB data. Returns a new EnrichmentResult."""
    if not api_key:
        raise ValueError("api_key is required for AbuseIPDB enrichment")

    if result.ioc_type != "ip":
        raise ValueError(f"AbuseIPDB only supports IP addresses, got: {result.ioc_type}")

    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": result.ioc,
        "maxAgeInDays": "90",
        "verbose": "",
    }

    response = get_json(_ABUSEIPDB_URL, headers=headers, params=params)
    data = response.get("data", {})

    if not data:
        _log.warning("Empty response data from AbuseIPDB for IP: %s", result.ioc)

    country_code = data.get("countryCode", "")

    return replace(
        result,
        abuse_score=data.get("abuseConfidenceScore", 0),
        abuse_total_reports=data.get("totalReports", 0),
        abuse_country=country_code,
        abuse_isp=data.get("isp", ""),
        country=country_code,
    )
