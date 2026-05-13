from unittest.mock import MagicMock, patch
import pytest
from src.enrichers.http_client import get_json, RateLimitError, ApiError


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
            with pytest.raises(RateLimitError):
                get_json("https://api.example.com", headers={}, params={})

    def test_raises_api_error_on_non_200(self):
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        with patch("src.enrichers.http_client.requests.get", return_value=mock_response):
            with pytest.raises(ApiError) as exc_info:
                get_json("https://api.example.com", headers={}, params={})
        assert "401" in str(exc_info.value)

    def test_raises_api_error_on_request_exception(self):
        import requests as req
        with patch("src.enrichers.http_client.requests.get", side_effect=req.RequestException("timeout")):
            with pytest.raises(ApiError) as exc_info:
                get_json("https://api.example.com", headers={}, params={})
        assert "timeout" in str(exc_info.value)
