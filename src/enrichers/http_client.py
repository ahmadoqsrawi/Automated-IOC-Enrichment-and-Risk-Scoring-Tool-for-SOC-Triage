import requests


class RateLimitError(Exception):
    """Raised when the API returns HTTP 429 Too Many Requests."""


class ApiError(Exception):
    """Raised when the API returns an unexpected error or the request fails."""


def get_json(url: str, headers: dict, params: dict, timeout: int = 10) -> dict:
    """Make a GET request and return parsed JSON. Raises RateLimitError or ApiError on failure."""
    try:
        response = requests.get(url, headers=headers, params=params, timeout=timeout)
    except requests.RequestException as exc:
        raise ApiError(str(exc)) from exc

    if response.status_code == 429:
        raise RateLimitError("AbuseIPDB rate limit reached. Try again later.")

    if response.status_code != 200:
        raise ApiError(f"HTTP {response.status_code}: {response.text[:200]}")

    return response.json()
