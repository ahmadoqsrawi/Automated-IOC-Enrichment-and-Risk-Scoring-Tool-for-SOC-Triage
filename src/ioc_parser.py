import ipaddress
import re
from typing import Literal

IOCType = Literal["ip", "url", "hash", "domain", "unknown"]

_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


def detect_ioc_type(ioc: str) -> IOCType:
    if not ioc or not ioc.strip():
        raise ValueError("IOC value must not be empty")

    value = ioc.strip()

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if value.startswith(("http://", "https://")):
        return "url"

    if _MD5_RE.match(value) or _SHA1_RE.match(value) or _SHA256_RE.match(value):
        return "hash"

    if _DOMAIN_RE.match(value):
        return "domain"

    return "unknown"


def normalize_ioc(ioc: str) -> str:
    if not ioc or not ioc.strip():
        raise ValueError("IOC value must not be empty")

    value = ioc.strip()

    if value.startswith(("http://", "https://")):
        # Only lowercase scheme+host, preserve case-sensitive path
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(value)
        normalized = urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        ))
        return normalized

    value = value.lower()
    if value.endswith("/"):
        value = value.rstrip("/")
    return value
