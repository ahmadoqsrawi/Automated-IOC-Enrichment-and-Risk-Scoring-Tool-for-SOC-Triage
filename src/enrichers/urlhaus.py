from src.enrichers.base import EnrichmentResult


def enrich_urlhaus(result: EnrichmentResult, auth_key: str = "") -> EnrichmentResult:
    raise NotImplementedError("URLhaus enricher not yet implemented (Phase 4)")
