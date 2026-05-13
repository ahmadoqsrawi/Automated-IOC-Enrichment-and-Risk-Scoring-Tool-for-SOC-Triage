from src.enrichers.base import EnrichmentResult
from src.scoring import compute_risk_score, get_verdict


class TestComputeRiskScore:
    def _make(self, **kwargs) -> EnrichmentResult:
        r = EnrichmentResult(ioc="test", ioc_type="ip")
        for k, v in kwargs.items():
            setattr(r, k, v)
        return r

    def test_clean_ip_is_low(self):
        r = self._make(vt_malicious=0, abuse_score=0, urlhaus_status="not_found")
        score, _ = compute_risk_score(r)
        assert score <= 20

    def test_high_vt_malicious_adds_40(self):
        r = self._make(vt_malicious=5, abuse_score=0, urlhaus_status="not_found")
        score, breakdown = compute_risk_score(r)
        assert breakdown["vt_malicious"] == 40
        assert score >= 40

    def test_medium_vt_malicious_adds_25(self):
        r = self._make(vt_malicious=2, abuse_score=0, urlhaus_status="not_found")
        _, breakdown = compute_risk_score(r)
        assert breakdown["vt_malicious"] == 25

    def test_high_abuse_score_adds_40(self):
        r = self._make(vt_malicious=0, abuse_score=92, urlhaus_status="not_found")
        score, breakdown = compute_risk_score(r)
        assert breakdown["abuse_score"] == 40

    def test_urlhaus_online_adds_40(self):
        r = self._make(vt_malicious=0, abuse_score=0, urlhaus_status="online")
        _, breakdown = compute_risk_score(r)
        assert breakdown["urlhaus"] == 40

    def test_urlhaus_offline_adds_25(self):
        r = self._make(vt_malicious=0, abuse_score=0, urlhaus_status="offline")
        _, breakdown = compute_risk_score(r)
        assert breakdown["urlhaus"] == 25

    def test_score_capped_at_100(self):
        r = self._make(vt_malicious=10, abuse_score=99, urlhaus_status="online")
        score, _ = compute_risk_score(r)
        assert score == 100


class TestGetVerdict:
    def test_low(self):
        assert get_verdict(10) == "low"

    def test_medium(self):
        assert get_verdict(35) == "medium"

    def test_high(self):
        assert get_verdict(65) == "high"

    def test_critical(self):
        assert get_verdict(85) == "critical"
