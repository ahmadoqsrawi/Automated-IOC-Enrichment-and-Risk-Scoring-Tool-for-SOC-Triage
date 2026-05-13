import base64
import logging
from dataclasses import replace
from typing import Any

from src.enrichers.base import EnrichmentResult
from src.enrichers.http_client import get_json

_log = logging.getLogger(__name__)
_VT_BASE = "https://www.virustotal.com/api/v3"


def _url_id(url: str) -> str:
    """Base64-encode a URL (no padding) to form a VirusTotal URL lookup ID."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _endpoint(ioc: str, ioc_type: str) -> str:
    if ioc_type == "ip":
        return f"{_VT_BASE}/ip_addresses/{ioc}"
    if ioc_type == "domain":
        return f"{_VT_BASE}/domains/{ioc}"
    if ioc_type == "hash":
        return f"{_VT_BASE}/files/{ioc}"
    if ioc_type == "url":
        return f"{_VT_BASE}/urls/{_url_id(ioc)}"
    raise ValueError(f"Unsupported IOC type: {ioc_type}")


def _extract(attrs: dict[str, Any]) -> dict[str, Any]:
    stats = attrs.get("last_analysis_stats", {})
    return {
        "vt_malicious": stats.get("malicious", 0),
        "vt_suspicious": stats.get("suspicious", 0),
        "vt_harmless": stats.get("harmless", 0),
        "vt_reputation": attrs.get("reputation", 0),
        "vt_tags": attrs.get("tags", []),
    }


def enrich_virustotal(result: EnrichmentResult, api_key: str) -> EnrichmentResult:
    """Enrich any IOC type with VirusTotal v3 data. Returns a new EnrichmentResult."""
    if not api_key:
        raise ValueError("api_key is required for VirusTotal enrichment")

    url = _endpoint(result.ioc, result.ioc_type)
    headers = {"x-apikey": api_key}

    response = get_json(url, headers=headers, params={})  # params required by signature; empty dict for VT API
    attrs = response.get("data", {}).get("attributes", {})

    if not attrs:
        _log.warning("Empty attributes from VirusTotal for %s (%s)", result.ioc, result.ioc_type)

    return replace(result, **_extract(attrs))
