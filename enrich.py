import argparse
import json
import os
import sys
from pathlib import Path

import pandas as pd
from tqdm import tqdm

from src.config import OUTPUT_DIR
from src.enrichers.mock import enrich_mock
from src.ioc_parser import detect_ioc_type, normalize_ioc
from src.reporting import generate_summary
from src.scoring import compute_risk_score, get_verdict


def process_iocs(input_path: str) -> list[dict]:
    df = pd.read_csv(input_path)
    if "ioc" not in df.columns:
        print("ERROR: Input CSV must have an 'ioc' column.")
        sys.exit(1)

    records = []
    for _, row in tqdm(df.iterrows(), total=len(df), desc="Enriching IOCs"):
        raw_ioc = str(row["ioc"])
        ioc = normalize_ioc(raw_ioc)
        ioc_type = str(row.get("type", "")).strip() or detect_ioc_type(ioc)

        result = enrich_mock(ioc, ioc_type)
        result.risk_score, result.score_breakdown = compute_risk_score(result)
        result.verdict = get_verdict(result.risk_score)
        result.summary = generate_summary(result)

        records.append({
            "ioc": result.ioc,
            "type": result.ioc_type,
            "verdict": result.verdict,
            "risk_score": result.risk_score,
            "vt_malicious": result.vt_malicious,
            "abuse_score": result.abuse_score,
            "urlhaus_status": result.urlhaus_status,
            "country": result.country,
            "asn": result.asn,
            "summary": result.summary,
        })

    return records


def write_csv(records: list[dict], output_path: Path) -> None:
    pd.DataFrame(records).to_csv(output_path, index=False)
    print(f"CSV report saved to {output_path}")


def write_json(records: list[dict], output_path: Path) -> None:
    with open(output_path, "w") as f:
        json.dump(records, f, indent=2)
    print(f"JSON report saved to {output_path}")


def write_markdown(records: list[dict], output_path: Path) -> None:
    from tabulate import tabulate

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
    print(f"Markdown report saved to {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="IOC Enrichment and Risk Scoring Tool")
    parser.add_argument("--input", required=True, help="Path to input CSV file")
    parser.add_argument("--output", default=None, help="Output file path (auto-named if omitted)")
    parser.add_argument("--format", choices=["csv", "json", "md"], default="csv", dest="fmt")
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    records = process_iocs(args.input)

    ext = {"csv": ".csv", "json": ".json", "md": ".md"}[args.fmt]
    output_path = Path(args.output) if args.output else OUTPUT_DIR / f"enriched_report{ext}"

    if args.fmt == "csv":
        write_csv(records, output_path)
    elif args.fmt == "json":
        write_json(records, output_path)
    else:
        write_markdown(records, output_path)


if __name__ == "__main__":
    main()
