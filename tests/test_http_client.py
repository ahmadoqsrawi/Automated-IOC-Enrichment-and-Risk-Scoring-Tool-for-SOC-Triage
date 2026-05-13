import requests
from unittest.mock import MagicMock, patch

import pytest

from src.enrichers.http_client import get_json, post_json, RateLimitError, ApiError


class TestGetJson:
    def test_returns_parsed_json_on_200(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"abuseConfidenceScore": 42}}

        with patch("src.enrichers.http_client.requests.get", return_value=mock_response):
            result = get_json("https://api.example.com", headers={}, params={})

        assert result == {"data": {"abuseConfidenceScore": 42}}

    def test_raises_rate_limit_error_on_429(self):
        mock_response = MagicMock()
        mock_response.status_code = 429

        with patch("src.enrichers.http_client.requests.get", return_value=mock_response):
            with pytest.raises(RateLimitError) as exc_info:
                get_json("https://api.example.com", headers={}, params={})
        assert "rate limit" in str(exc_info.value).lower()

    def test_raises_api_error_on_non_200(self):
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        with patch("src.enrichers.http_client.requests.get", return_value=mock_response):
            with pytest.raises(ApiError) as exc_info:
                get_json("https://api.example.com", headers={}, params={})
        assert "401" in str(exc_info.value)

    def test_raises_api_error_on_request_exception(self):
        with patch("src.enrichers.http_client.requests.get", side_effect=requests.RequestException("timeout")):
            with pytest.raises(ApiError) as exc_info:
                get_json("https://api.example.com", headers={}, params={})
        assert "timeout" in str(exc_info.value)

    def test_raises_api_error_on_invalid_json(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")

        with patch("src.enrichers.http_client.requests.get", return_value=mock_response):
            with pytest.raises(ApiError) as exc_info:
                get_json("https://api.example.com", headers={}, params={})
        assert "Invalid JSON" in str(exc_info.value)

    def test_raises_value_error_on_non_positive_timeout(self):
        with pytest.raises(ValueError, match="timeout must be positive"):
            get_json("https://api.example.com", headers={}, params={}, timeout=0)


class TestPostJson:
    def test_returns_parsed_json_on_200(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"key": "value"}

        with patch("src.enrichers.http_client.requests.post", return_value=mock_response):
            result = post_json("https://example.com/api", headers={}, data={"field": "val"})

        assert result == {"key": "value"}

    def test_raises_rate_limit_error_on_429(self):
        mock_response = MagicMock()
        mock_response.status_code = 429

        with patch("src.enrichers.http_client.requests.post", return_value=mock_response):
            with pytest.raises(RateLimitError):
                post_json("https://example.com/api", headers={}, data={})

    def test_raises_api_error_on_non_200(self):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Server Error"

        with patch("src.enrichers.http_client.requests.post", return_value=mock_response):
            with pytest.raises(ApiError, match="HTTP 500"):
                post_json("https://example.com/api", headers={}, data={})

    def test_raises_api_error_on_invalid_json(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")

        with patch("src.enrichers.http_client.requests.post", return_value=mock_response):
            with pytest.raises(ApiError, match="Invalid JSON"):
                post_json("https://example.com/api", headers={}, data={})

    def test_raises_api_error_on_connection_error(self):
        with patch("src.enrichers.http_client.requests.post", side_effect=requests.ConnectionError("refused")):
            with pytest.raises(ApiError):
                post_json("https://example.com/api", headers={}, data={})

    def test_raises_value_error_on_non_positive_timeout(self):
        with pytest.raises(ValueError, match="timeout"):
            post_json("https://example.com/api", headers={}, data={}, timeout=0)
