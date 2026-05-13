import logging
from dataclasses import replace

from src.enrichers.base import EnrichmentResult
from src.enrichers.http_client import post_json

_log = logging.getLogger(__name__)
_URLHAUS_BASE = "https://urlhaus-api.abuse.ch/v1"


def _build_request(ioc: str, ioc_type: str) -> tuple[str, dict[str, str]]:
    if ioc_type == "url":
        return f"{_URLHAUS_BASE}/url/", {"url": ioc}
    if ioc_type in ("ip", "domain"):
        return f"{_URLHAUS_BASE}/host/", {"host": ioc}
    if ioc_type == "hash":
        if len(ioc) == 64:
            return f"{_URLHAUS_BASE}/payload/", {"sha256_hash": ioc}
        return f"{_URLHAUS_BASE}/payload/", {"md5_hash": ioc}
    raise ValueError(f"URLhaus does not support IOC type: {ioc_type}")


def _parse_url_response(response: dict) -> dict:
    status = response.get("url_status", "")
    return {
        "urlhaus_status": status if status in ("online", "offline") else "not_found",
        "urlhaus_threat": response.get("threat", ""),
        "urlhaus_tags": response.get("tags", []) or [],
    }


def _parse_host_response(response: dict) -> dict:
    urls = response.get("urls", [])
    statuses = [u.get("url_status", "") for u in urls]
    urlhaus_status = "online" if "online" in statuses else ("offline" if "offline" in statuses else "not_found")
    threat = next((u.get("threat", "") for u in urls if u.get("threat")), "")
    tags: list[str] = list({tag for u in urls for tag in (u.get("tags") or [])})
    return {"urlhaus_status": urlhaus_status, "urlhaus_threat": threat, "urlhaus_tags": tags}


def _parse_hash_response(response: dict) -> dict:
    if response.get("query_status") == "no_results":
        return {"urlhaus_status": "not_found", "urlhaus_threat": "", "urlhaus_tags": []}
    return {
        "urlhaus_status": "online",
        "urlhaus_threat": response.get("threat", ""),
        "urlhaus_tags": response.get("tags", []) or [],
    }


def enrich_urlhaus(result: EnrichmentResult, auth_key: str = "") -> EnrichmentResult:
    endpoint, data = _build_request(result.ioc, result.ioc_type)
    headers: dict[str, str] = {}
    if auth_key:
        headers["Auth-Key"] = auth_key

    response = post_json(endpoint, headers=headers, data=data)
    query_status = response.get("query_status", "")

    if query_status == "no_results":
        fields: dict = {"urlhaus_status": "not_found", "urlhaus_threat": "", "urlhaus_tags": []}
    elif result.ioc_type == "url":
        fields = _parse_url_response(response)
    elif result.ioc_type in ("ip", "domain"):
        fields = _parse_host_response(response)
    else:
        fields = _parse_hash_response(response)

    return replace(result, **fields)
