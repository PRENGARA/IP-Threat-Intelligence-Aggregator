# IP Threat Intelligence Aggregator

A Python command-line utility for **defensive IP indicator-of-compromise (IOC) triage**. It queries up to three public intelligence APIs—**AbuseIPDB, VirusTotal, and AlienVault OTX**—and combines source-specific evidence into an **explainable, heuristic severity score**. Designed as a compact security-automation portfolio project.

> **Research relevance:** Multi-source telemetry enrichment, evidence provenance, indicator correlation, explainable risk scoring, and reproducible security evaluation. This project is **not a trained machine-learning model**, a benchmark study, an intrusion-detection engine, or an automated penetration-testing system.

## Features

| Capability | Implementation |
|---|---|
| Multi-source enrichment | AbuseIPDB check, VirusTotal IP reputation, AlienVault OTX IP indicator |
| Context / IOCs | VT communicating file hashes and DNS resolutions; OTX malware associations and passive DNS |
| Explainable triage | Risk score 0–100, severity bands, and human-readable contributing reasons |
| Partial configuration | Skips providers with no API key; reports provider errors individually |
| Analyst workflows | Single-IP lookup, newline-delimited batch IP lookup, human-readable or JSON output |
| Defensive controls | IP syntax validation; per-request timeout; maximum related-IOC result cap; no active scanning |

## Repository structure

```text
.
├── ioc_lookup.py         # Source code / CLI
├── README.md             # Setup, methodology, findings, limitations
├── requirements.txt      # Python dependency
├── .env.example          # Environment-variable names (no credentials)
├── .gitignore            # Excludes secrets and analyst output
├── FINDINGS.md           # Code-derived observations and next experiments
└── tests/
    └── test_scoring.py  # Offline deterministic scoring tests
```

## Prerequisites

- Python 3.9+ on Linux, macOS, or Windows (Linux is the primary development environment).
- Internet access and at least one valid provider API key for live enrichments. Provider account tiers and quotas vary.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
export ABUSEIPDB_API_KEY='your_key_here'
export VT_API_KEY='your_key_here'
export OTX_API_KEY='your_key_here'
```

API-key signup: [AbuseIPDB](https://www.abuseipdb.com/account/api), [VirusTotal](https://www.virustotal.com/gui/my-apikey), [AlienVault OTX](https://otx.alienvault.com/api).

Only configure providers you intend to use. Avoid sharing screenshots or JSON files containing sensitive IP addresses. The program reads secrets from environment variables; never hard-code keys or commit `.env` files.

## Usage

```bash
python ioc_lookup.py 8.8.8.8
python ioc_lookup.py 8.8.8.8 --json
python ioc_lookup.py 8.8.8.8 --json --out result.json
printf '8.8.8.8\n1.1.1.1\n' > ips.txt
python ioc_lookup.py --batch ips.txt --json --out results.json
```

`--out` writes JSON even without `--json`. `--json` prints machine-readable JSON to stdout **but note** that an unconfigured-provider warning can also appear on stdout if all keys are missing. Do not feed stdout directly to a strict JSON parser in that state.

### JSON schema (illustrative; not a live threat verdict)

```json
{
  "ip": "8.8.8.8",
  "queried_at_utc": "<ISO-8601 UTC timestamp>",
  "severity": {"score": 0, "band": "Clean / No Signal", "reasons": []},
  "sources": {
    "abuseipdb": {"source": "AbuseIPDB", "configured": false, "ok": false},
    "virustotal": {"source": "VirusTotal", "configured": false, "ok": false},
    "otx": {"source": "AlienVault OTX", "configured": false, "ok": false}
  },
  "related_iocs": {"hashes": [], "domains": []}
}
```

**Important:** a zero score with missing/failed sources means **no evidence collected**, not proof that an IP is safe. Do not block, allowlist, or make attribution claims based on this score alone.

## Scoring methodology

The program calculates the following **heuristic** components; these weights are design choices, **not statistically calibrated**:

| Signal | Contribution |
|---|---|
| AbuseIPDB confidence | 40% of reported confidence (0–40) |
| AbuseIPDB Tor indicator | +10 if marked a Tor exit node |
| VirusTotal reputation flags | `min(8 × malicious + 3 × suspicious, 40)` |
| VT malicious communicating files | `min(2 × count + 0.3 × mean malicious detections, 45)` |
| OTX pulse references | `min(4 × pulse count, 20)` |

The total is rounded and capped at 100. Bands: **Clean / No Signal** (0), **Low** (1–19), **Medium** (20–49), **High** (50–79), **Critical** (80–100).

The program retains per-provider outputs and reason strings so analysts can trace why the verdict was assigned. **Do not interpret 80/100 as an 80% probability of maliciousness.** Scores vary based on data coverage, API quotas, time windows, and provider policies.

## Observations and limitations

- Data are **read-only API lookups**, not independently validated detections or ground-truth labels.
- Supporting domains and hashes are **associated indicators**, not necessarily malicious themselves; passive DNS and shared infrastructure can lead to false associations.
- Provider errors and unavailable APIs reduce coverage; current scoring does not normalize for the number of providers successfully queried.
- `Clean / No Signal` conflates clean reputations with missing evidence. Treat these cases separately in operational decisions.
- The OTX endpoints in the current source are hardcoded for **IPv4**, although the input validator permits IPv6. OTX IPv6 lookups therefore require additional support.
- Related indicators from different sources are concatenated, not normalized or deduplicated.
- Subsequent VT/OTX relationship lookups can fail without separate detailed error fields; the base provider result may still report success.
- Batch processing is serial, with 0.2-second inter-provider pauses and a 30-second timeout per request; retry/backoff and API-rate-limit handling are not implemented.
- No test corpus, baseline comparison, ground-truth validation, calibration, statistical evaluation, dashboard UI, or learning-based inference has been provided.

See [FINDINGS.md](FINDINGS.md) for evidence, design decisions, and a research-oriented improvement plan.

## Testing

Offline tests cover IP validation, severity boundaries, signal components, and no-data behavior without contacting third-party services:

```bash
python -m unittest discover -s tests -v
```

Tests prove these **local code paths**, not the external APIs' current behavior. Live runs require keys, connectivity, and provider access.

## Responsible use

Use this tool for authorized security operations and research. Treat external threat-intelligence metadata as untrusted and potentially incomplete. Respect provider terms, rate limits, privacy requirements, and data-retention policies.

## Research extension ideas

1. Build a labeled, time-split evaluation set and compare each data source's precision, recall, latency, and coverage.
2. Add provenance records for every source, timestamp, request outcome, and enrichment edge.
3. Implement confidence-aware scoring with **unknown** outcomes, source-availability normalization, and calibration.
4. Evaluate graph-based relationships among IPs, domains, hashes, and alerts in an isolated detection testbed.
5. Expose a documented API or dashboard once backend behavior and privacy constraints are validated.

## Author

Priyadharshini Rengaramanujam — cybersecurity research/engineering portfolio. Add your GitHub profile URL and an appropriate license before publishing.
