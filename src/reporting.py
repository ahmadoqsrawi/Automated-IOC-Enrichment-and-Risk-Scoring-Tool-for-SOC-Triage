from src.enrichers.base import EnrichmentResult


def generate_summary(result: EnrichmentResult) -> str:
    """Generate a SOC analyst summary. Requires result.verdict to be pre-populated."""
    if not result.verdict:
        raise ValueError("EnrichmentResult.verdict must be set before generating a summary")

    parts = []

    if result.vt_malicious >= 5:
        parts.append(f"VirusTotal shows {result.vt_malicious} malicious detections")
    elif result.vt_malicious >= 1:
        parts.append(f"VirusTotal shows {result.vt_malicious} malicious detection(s)")

    if result.abuse_score >= 10:
        parts.append(f"AbuseIPDB reports an abuse confidence score of {result.abuse_score}")

    if result.urlhaus_status == "online":
        parts.append("URLhaus reports this IOC as an active malware source")
    elif result.urlhaus_status == "offline":
        parts.append("URLhaus reports this IOC as a previously active malware source")

    if not parts:
        return "No strong malicious indicators found across checked sources."

    summary = f"This {result.ioc_type} is {result.verdict} risk. " + "; ".join(parts) + "."

    if result.verdict in ("high", "critical"):
        summary += " Recommended action: block immediately, search SIEM logs for communication, and investigate affected hosts."

    return summary
