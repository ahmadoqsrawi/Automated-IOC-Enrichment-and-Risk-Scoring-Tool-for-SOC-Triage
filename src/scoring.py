from src.enrichers.base import EnrichmentResult


def compute_risk_score(result: EnrichmentResult) -> tuple[int, dict]:
    breakdown: dict[str, int] = {}

    if result.vt_malicious >= 5:
        breakdown["vt_malicious"] = 40
    elif result.vt_malicious >= 1:
        breakdown["vt_malicious"] = 25
    else:
        breakdown["vt_malicious"] = 0

    breakdown["vt_suspicious"] = 10 if result.vt_suspicious >= 1 else 0

    if result.abuse_score >= 90:
        breakdown["abuse_score"] = 40
    elif result.abuse_score >= 50:
        breakdown["abuse_score"] = 25
    elif result.abuse_score >= 10:
        breakdown["abuse_score"] = 10
    else:
        breakdown["abuse_score"] = 0

    if result.urlhaus_status == "online":
        breakdown["urlhaus"] = 40
    elif result.urlhaus_status == "offline":
        breakdown["urlhaus"] = 25
    else:
        breakdown["urlhaus"] = 0

    score = min(sum(breakdown.values()), 100)
    return score, breakdown


def get_verdict(score: int) -> str:
    if score <= 20:
        return "low"
    if score <= 50:
        return "medium"
    if score <= 80:
        return "high"
    return "critical"
