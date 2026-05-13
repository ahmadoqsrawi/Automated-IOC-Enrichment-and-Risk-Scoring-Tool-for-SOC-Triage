import logging
from typing import Any

import requests

_log = logging.getLogger(__name__)

_MAX_ERROR_TEXT = 200


class RateLimitError(Exception):
    """Raised when the API returns HTTP 429 Too Many Requests."""


class ApiError(Exception):
    """Raised when the API returns an unexpected error or the request fails."""


def get_json(url: str, headers: dict[str, str], params: dict[str, Any], timeout: int = 10) -> dict[str, Any]:
    """Make a GET request and return parsed JSON. Raises RateLimitError or ApiError on failure."""
    if timeout <= 0:
        raise ValueError(f"timeout must be positive, got {timeout}")

    try:
        response = requests.get(url, headers=headers, params=params, timeout=timeout)
    except requests.RequestException as exc:
        _log.error("Request to %s failed: %s", url, exc)
        raise ApiError(str(exc)) from exc

    if response.status_code == 429:
        raise RateLimitError("AbuseIPDB rate limit reached. Try again later.")

    if response.status_code != 200:
        raise ApiError(f"HTTP {response.status_code}: {response.text[:_MAX_ERROR_TEXT]}")

    try:
        return response.json()
    except ValueError as exc:
        raise ApiError(f"Invalid JSON response from {url}: {exc}") from exc


def post_json(
    url: str,
    headers: dict[str, str],
    data: dict[str, str],
    timeout: int = 10,
) -> dict[str, Any]:
    """Make a POST request with form-encoded data and return parsed JSON. Raises RateLimitError or ApiError on failure."""
    if timeout <= 0:
        raise ValueError(f"timeout must be positive, got {timeout}")

    try:
        response = requests.post(url, headers=headers, data=data, timeout=timeout)
    except requests.RequestException as exc:
        _log.error("Request to %s failed: %s", url, exc)
        raise ApiError(str(exc)) from exc

    if response.status_code == 429:
        raise RateLimitError(f"Rate limit exceeded for {url}")

    if response.status_code != 200:
        raise ApiError(f"HTTP {response.status_code}: {response.text[:_MAX_ERROR_TEXT]}")

    try:
        return response.json()
    except ValueError as exc:
        raise ApiError(f"Invalid JSON response from {url}: {exc}") from exc
