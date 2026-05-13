from src.enrichers.base import EnrichmentResult
from src.reporting import generate_summary


def _make(**kwargs) -> EnrichmentResult:
    defaults = dict(
        ioc="1.2.3.4",
        ioc_type="ip",
        vt_malicious=0,
        abuse_score=0,
        urlhaus_status="not_found",
        risk_score=0,
        verdict="low",
    )
    return EnrichmentResult(**(defaults | kwargs))


class TestGenerateSummary:
    def test_clean_ioc_returns_no_indicators(self):
        r = _make(risk_score=5, verdict="low")
        summary = generate_summary(r)
        assert "no strong malicious" in summary.lower()

    def test_high_vt_mentioned_in_summary(self):
        r = _make(risk_score=65, verdict="high", vt_malicious=8)
        summary = generate_summary(r)
        assert "virustotal" in summary.lower()
        assert "8" in summary

    def test_high_abuse_mentioned_in_summary(self):
        r = _make(risk_score=75, verdict="high", abuse_score=92)
        summary = generate_summary(r)
        assert "abuseipdb" in summary.lower()
        assert "92" in summary

    def test_urlhaus_online_mentioned(self):
        r = _make(risk_score=80, verdict="high", urlhaus_status="online")
        summary = generate_summary(r)
        assert "urlhaus" in summary.lower()

    def test_critical_verdict_includes_recommended_action(self):
        r = _make(risk_score=90, verdict="critical", vt_malicious=10)
        summary = generate_summary(r)
        assert "recommended action" in summary.lower() or "block" in summary.lower()
