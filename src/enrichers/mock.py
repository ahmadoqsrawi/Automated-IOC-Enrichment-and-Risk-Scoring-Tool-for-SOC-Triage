from src.enrichers.base import EnrichmentResult


_MOCK_DATA = {
    "ip": {
        "vt_malicious": 0,
        "vt_suspicious": 0,
        "vt_harmless": 70,
        "vt_reputation": 0,
        "abuse_score": 0,
        "abuse_total_reports": 0,
        "abuse_country": "US",
        "abuse_isp": "Google LLC",
        "country": "US",
        "asn": "AS15169 Google LLC",
    },
    "domain": {
        "vt_malicious": 3,
        "vt_suspicious": 1,
        "vt_harmless": 50,
        "vt_reputation": -5,
        "urlhaus_status": "offline",
        "urlhaus_threat": "malware_download",
        "country": "RU",
        "asn": "AS12389 Rostelecom",
    },
    "url": {
        "vt_malicious": 8,
        "vt_suspicious": 2,
        "vt_harmless": 5,
        "urlhaus_status": "online",
        "urlhaus_threat": "exe",
        "urlhaus_tags": ["malware", "exe"],
        "country": "NL",
        "asn": "AS60781 LeaseWeb",
    },
    "hash": {
        "vt_malicious": 55,
        "vt_suspicious": 3,
        "vt_harmless": 0,
        "vt_tags": ["trojan", "ransomware"],
    },
}


def enrich_mock(ioc: str, ioc_type: str) -> EnrichmentResult:
    defaults = _MOCK_DATA.get(ioc_type, {})
    return EnrichmentResult(ioc=ioc, ioc_type=ioc_type, **defaults)
