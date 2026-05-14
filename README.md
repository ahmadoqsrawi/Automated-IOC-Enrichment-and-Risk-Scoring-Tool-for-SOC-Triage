# Automated IOC Enrichment and Risk Scoring Tool for SOC Triage

A Python CLI tool that takes a CSV of Indicators of Compromise (IPs, domains, URLs, file hashes), queries three threat intel APIs, computes a weighted risk score per IOC, and outputs a grouped SOC triage report in CSV, JSON, or Markdown.

## Problem

SOC analysts get dozens to hundreds of alerts per shift. Each one might have raw IOCs that need to be checked across VirusTotal, AbuseIPDB, and URLhaus before any triage decision can be made. Doing that manually for 50 IPs takes 30 to 60 minutes. This tool does it in under 60 seconds.

## SOC use case

A SIEM fires alerts for outbound connections to unknown IPs and downloads of suspicious executables. The analyst exports the flagged IOCs to a CSV and runs this tool. The output is a risk-scored report grouped by severity (critical / high / medium / low) with plain-language summaries and recommended actions.

This is built for L1/L2 SOC analysts during alert triage, threat hunters during incident investigation, and blue team engineers building detection pipelines.

## Dataset

The tool queries three live threat intelligence sources. No static datasets are used — all data is pulled from APIs at runtime.

| Source | IOC Types | What it provides |
|--------|-----------|-----------------|
| [VirusTotal v3](https://www.virustotal.com) | IP, Domain, URL, Hash | Malicious/suspicious detection counts across 70+ AV engines, reputation score, tags |
| [AbuseIPDB v2](https://www.abuseipdb.com) | IP only | Abuse confidence score (0-100), total reports, country, ISP |
| [URLhaus](https://urlhaus.abuse.ch) | URL, IP, Domain, Hash | Malware hosting status (online/offline), threat category, tags |

## Detection logic

Risk scoring uses a weighted bucket model across all three sources, capped at 100.

### Scoring Weights

| Signal | Condition | Points |
|--------|-----------|--------|
| VirusTotal malicious detections | 5 or more engines | 40 |
| VirusTotal malicious detections | 1 to 4 engines | 25 |
| VirusTotal suspicious detections | 1 or more engines | 10 |
| AbuseIPDB confidence score | 90 or above | 40 |
| AbuseIPDB confidence score | 50 to 89 | 25 |
| AbuseIPDB confidence score | 10 to 49 | 10 |
| URLhaus status | online (active malware host) | 40 |
| URLhaus status | offline (historical) | 25 |

### Verdict Tiers

| Score | Verdict | Recommended Action |
|-------|---------|--------------------|
| 0 to 20 | Low | Monitor, no immediate action |
| 21 to 50 | Medium | Investigate, check SIEM for related activity |
| 51 to 80 | High | Prioritize investigation, consider blocking |
| 81 to 100 | Critical | Block immediately, hunt for lateral movement |

### IOC Type Detection

IOCs are auto-detected from the raw value:
- IP: validated with Python `ipaddress` module (IPv4 and IPv6)
- URL: case-insensitive http:// or https:// prefix check
- Hash: MD5 (32 chars), SHA1 (40 chars), SHA256 (64 chars) via regex
- Domain: validated with domain regex after ruling out the above
- Unknown: anything that does not match is skipped by all enrichers

## AI/ML method

The tool uses a rule-based weighted scoring model rather than a trained ML classifier. This is intentional for a SOC context. Every score traces back to specific API signals with no black box, so analysts can audit exactly why an IOC scored 90. It works on day one with no training data, and the same IOC always produces the same score given the same API responses.

Each output record includes a score_breakdown field showing the exact contribution from each source. These fields are designed to serve as features in a supervised classifier (XGBoost or similar) once labelled ground-truth data is available from closed incidents.

## MITRE ATT&CK mapping

| Technique | ID | How this tool helps |
|-----------|----|---------------------|
| Command and Control | T1071 | Enriches C2 IPs and domains with abuse scores and VT detections |
| Phishing | T1566 | Enriches malicious URLs used in phishing lures |
| Ingress Tool Transfer | T1105 | Checks file hashes of downloaded payloads against VT and URLhaus |
| Web Service (C2) | T1102 | Detects malicious domains used for C2 over web protocols |
| Exploit Public-Facing Application | T1190 | Flags IPs associated with scanning and exploitation |
| Malware - Dropper | T1587.001 | Hash enrichment detects known dropper samples |
| Acquire Infrastructure | T1583 | Surfaces bulletproof hosting IPs and domains |

## Screenshots

Running the tool:

```
$ ./run.sh --input iocs.csv --format md

Enriching IOCs: 100%|██████████| 18/18 [00:12<00:00,  1.4it/s]
Markdown report saved to reports/enriched_report.md
```

See [sample_output/enriched_report.md](sample_output/enriched_report.md) for a full real report.

Critical IOC example:

| IOC | Type | Score | Summary |
|-----|------|-------|---------|
| 185.220.101.45 | ip | 90 | This ip is critical risk. VirusTotal shows 15 malicious detections; AbuseIPDB reports an abuse confidence score of 100. Block immediately, search SIEM logs for communication, and investigate affected hosts. |

JSON output example:

```json
{
  "ioc": "185.220.101.45",
  "type": "ip",
  "verdict": "critical",
  "risk_score": 90,
  "vt_malicious": 15,
  "vt_suspicious": 4,
  "abuse_score": 100,
  "urlhaus_status": "not_found",
  "country": "DE",
  "summary": "This ip is critical risk. VirusTotal shows 15 malicious detections; AbuseIPDB reports an abuse confidence score of 100."
}
```

## How to run

You need Python 3.11+ and API keys for VirusTotal, AbuseIPDB, and URLhaus (all free).

```bash
git clone https://github.com/ahmadoqsrawi/Automated-IOC-Enrichment-and-Risk-Scoring-Tool-for-SOC-Triage.git
cd Automated-IOC-Enrichment-and-Risk-Scoring-Tool-for-SOC-Triage

python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# add your API keys to .env
```

Prepare a CSV with an `ioc` column:

```csv
ioc
185.220.101.45
emotet-c2.ru
https://malware.example.com/payload.exe
44d88612fea8a8f36de82e1278abb02f
```

Run it:

```bash
./run.sh --input iocs.csv --format csv    # spreadsheet
./run.sh --input iocs.csv --format json   # raw data
./run.sh --input iocs.csv --format md     # analyst report
```

Output goes to the `reports/` folder. The `run.sh` wrapper handles venv activation automatically.

### API Keys

| API | Sign up | Free tier |
|-----|---------|-----------|
| VirusTotal | [virustotal.com](https://www.virustotal.com) | 500 req/day, 4 req/min |
| AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com) | 1,000 req/day |
| URLhaus | [abuse.ch](https://auth.abuse.ch/login) | Free with account |

## Limitations

- Free API tiers have rate limits. Large IOC lists (500+) will hit them and those IOCs get skipped with a warning.
- AbuseIPDB only supports IP lookups. Domains, URLs, and hashes are not enriched by that source.
- Each run is a point-in-time snapshot. There is no tracking of how an IOC's reputation changes over time.
- VirusTotal v3 does not support SHA1 hashes for file lookups. SHA1 IOCs are detected but not enriched.
- IOCs that don't match any known pattern are classified as unknown and skipped.
- Duplicate IOCs in the input CSV are enriched multiple times.

## Future improvements

- Shodan integration for open port and service fingerprinting on IPs
- WHOIS enrichment for domain registration age and registrar data
- Async enrichment to run API calls in parallel and cut runtime
- STIX 2.1 export for sharing with threat intel platforms
- Trained risk classifier using score breakdown fields as ML features
- Sigma rule generation from high-scoring IOCs
- Web UI for non-CLI users
