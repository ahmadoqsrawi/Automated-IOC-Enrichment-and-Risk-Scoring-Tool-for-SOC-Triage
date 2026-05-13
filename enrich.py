import argparse
import json
import logging
import sys
from dataclasses import replace
from pathlib import Path

import pandas as pd
from tabulate import tabulate
from tqdm import tqdm

from src.config import OUTPUT_DIR
from src.enrichers.mock import enrich_mock
from src.ioc_parser import detect_ioc_type, normalize_ioc
from src.reporting import generate_summary
from src.scoring import compute_risk_score, get_verdict

logging.basicConfig(level=logging.INFO, format="%(message)s")
_log = logging.getLogger(__name__)


def process_iocs(input_path: str) -> list[dict]:
    path = Path(input_path)
    if not path.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    df = pd.read_csv(path)
    if "ioc" not in df.columns:
        raise ValueError("Input CSV must have an 'ioc' column.")

    records = []
    for _, row in tqdm(df.iterrows(), total=len(df), desc="Enriching IOCs"):
        raw_ioc = str(row["ioc"])
        ioc = normalize_ioc(raw_ioc)
        ioc_type = str(row.get("type", "")).strip() or detect_ioc_type(ioc)

        enriched = enrich_mock(ioc, ioc_type)
        risk_score, score_breakdown = compute_risk_score(enriched)
        verdict = get_verdict(risk_score)

        # Build a new result with computed fields populated
        enriched = replace(enriched, risk_score=risk_score, score_breakdown=score_breakdown, verdict=verdict)
        summary = generate_summary(enriched)

        records.append({
            "ioc": enriched.ioc,
            "type": enriched.ioc_type,
            "verdict": verdict,
            "risk_score": risk_score,
            "vt_malicious": enriched.vt_malicious,
            "abuse_score": enriched.abuse_score,
            "urlhaus_status": enriched.urlhaus_status,
            "country": enriched.country,
            "asn": enriched.asn,
            "summary": summary,
        })

    return records


def write_csv(records: list[dict], output_path: Path) -> None:
    pd.DataFrame(records).to_csv(output_path, index=False)
    _log.info("CSV report saved to %s", output_path)


def write_json(records: list[dict], output_path: Path) -> None:
    with open(output_path, "w") as f:
        json.dump(records, f, indent=2)
    _log.info("JSON report saved to %s", output_path)


def write_markdown(records: list[dict], output_path: Path) -> None:
    verdicts = [r["verdict"] for r in records]
    counts = {v: verdicts.count(v) for v in ("critical", "high", "medium", "low")}

    lines = [
        "# IOC Enrichment Report\n",
        "## Summary\n",
        f"Total IOCs analyzed: {len(records)}  ",
        f"Critical: {counts.get('critical', 0)}  ",
        f"High: {counts.get('high', 0)}  ",
        f"Medium: {counts.get('medium', 0)}  ",
        f"Low: {counts.get('low', 0)}  \n",
    ]

    for verdict in ("critical", "high", "medium", "low"):
        group = [r for r in records if r["verdict"] == verdict]
        if not group:
            continue
        lines.append(f"## {verdict.capitalize()} IOCs\n")
        table_rows = [[r["ioc"], r["type"], r["risk_score"], r["summary"]] for r in group]
        lines.append(tabulate(table_rows, headers=["IOC", "Type", "Score", "Summary"], tablefmt="github"))
        lines.append("")

    with open(output_path, "w") as f:
        f.write("\n".join(lines))
    _log.info("Markdown report saved to %s", output_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="IOC Enrichment and Risk Scoring Tool")
    parser.add_argument("--input", required=True, help="Path to input CSV file")
    parser.add_argument("--output", default=None, help="Output file path (auto-named if omitted)")
    parser.add_argument("--format", choices=["csv", "json", "md"], default="csv", dest="fmt")
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    try:
        records = process_iocs(args.input)
    except (FileNotFoundError, ValueError) as exc:
        _log.error("ERROR: %s", exc)
        sys.exit(1)

    ext = {"csv": ".csv", "json": ".json", "md": ".md"}[args.fmt]
    output_path: Path = Path(args.output) if args.output else OUTPUT_DIR / f"enriched_report{ext}"

    if args.fmt == "csv":
        write_csv(records, output_path)
    elif args.fmt == "json":
        write_json(records, output_path)
    else:
        write_markdown(records, output_path)


if __name__ == "__main__":
    main()
