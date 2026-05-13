from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EnrichmentResult:
    ioc: str
    ioc_type: str

    # VirusTotal fields
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_harmless: int = 0
    vt_reputation: int = 0
    vt_tags: list = field(default_factory=list)

    # AbuseIPDB fields (IPs only)
    abuse_score: int = 0
    abuse_total_reports: int = 0
    abuse_country: str = ""
    abuse_isp: str = ""

    # URLhaus fields
    urlhaus_status: str = "not_found"
    urlhaus_threat: str = ""
    urlhaus_tags: list = field(default_factory=list)

    # GeoIP / context
    country: str = ""
    asn: str = ""

    # Computed later
    risk_score: int = 0
    verdict: str = ""
    summary: str = ""
    score_breakdown: dict = field(default_factory=dict)
