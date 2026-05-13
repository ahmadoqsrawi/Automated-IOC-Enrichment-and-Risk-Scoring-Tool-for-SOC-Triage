from src.enrichers.base import EnrichmentResult


def enrich_virustotal(result: EnrichmentResult, api_key: str) -> EnrichmentResult:
    raise NotImplementedError("VirusTotal enricher not yet implemented (Phase 3)")
