import ipaddress
import re


_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def detect_ioc_type(ioc: str) -> str:
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

    return "domain"


def normalize_ioc(ioc: str) -> str:
    value = ioc.strip().lower()
    if not value.startswith(("http://", "https://")) and value.endswith("/"):
        value = value.rstrip("/")
    return value
