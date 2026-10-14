# Findings and technical review

## Scope of evidence
These findings are derived from **static inspection of the supplied Python source** and deterministic offline tests, **not from live AbuseIPDB, VirusTotal, or OTX query results**. There is no empirical claim of detection accuracy, analyst time saved, benchmark superiority, or reduced false positives.

## Essential findings

1. **Cross-source aggregation is implemented.** `lookup_ip` combines AbuseIPDB, VirusTotal and OTX outputs, preserving per-source response objects under `sources` and related hashes/domains under `related_iocs`.
2. **The score is explainable but heuristic.** `compute_severity` merges abuse-confidence, Tor status, VT flags, malicious communicating files, and OTX pulse associations. Capped sub-scores contribute to a final 0–100 band and human-readable reasons.
3. **The workflow supports triage and integration.** Human-readable terminal output, JSON output, optional JSON file writing, and file-driven IP batches exist in the CLI.
4. **Input validation and resilient partial results exist.** Invalid IP syntax is rejected; missing provider keys skip that provider; networking exceptions and non-200 responses are captured.
5. **Missing evidence can look like a clean verdict.** A score of 0 is labeled `Clean / No Signal` even if no API keys are supplied or providers fail. An analyst should use provider status before interpreting this band.
6. **Related IOC attribution requires caution.** VT communicating-file hashes and resolution domains and OTX malware/passive-DNS associations are linked context, not independently proven malicious infrastructure.
7. **IPv6 coverage is incomplete.** `validate_ip` accepts IPv6, but OTX request routes use `/IPv4/`.
8. **Scoring calibration is not established.** No labeled corpus, false-positive/false-negative analysis, accuracy metric, baselines, or temporal evaluation is part of the supplied code.
9. **Provider and rate-limit robustness need work.** No exponential backoff, 429-specific strategy, caching, concurrent batching, or pagination beyond the first related-IOC page is implemented.
10. **This is a CLI project, not a dashboard.** Any portfolio or application description should call it an IOC enrichment/triage tool, unless a separate dashboard implementation is supplied.

## Suggested experimental plan

- **Question:** Does multi-source enrichment improve analyst triage over individual API signals?
- **Hypothesis to test, not a finding:** Combined evidence may improve detection coverage but can also amplify correlated or stale reputation signals.
- **Dataset:** Curate a permissioned sample of benign and malicious IP indicators, recording independent labels, observation times, and evidence provenance. Use a time-separated holdout set.
- **Baselines:** Individual-provider signals, simple majority vote, current weighted heuristic, and a tuned interpretable statistical baseline.
- **Metrics:** Precision, recall, F1, PR-AUC where applicable, false-positive rate, abstention/unknown rate, provider coverage, API latency, and per-IP cost.
- **Ablations:** Remove each provider and each related-IOC feature; assess stability across changes in provider availability and data freshness.
- **Threats to validity:** Selection bias, label leakage, stale/missing context, shared infrastructure, correlated feeds, rate limiting, and reputation drift.

## Evidence map

- `query_abuseipdb`, `query_virustotal`, `query_otx`: provider parsing and related indicator collection.
- `compute_severity`: weighted components and bands.
- `lookup_ip`: validation, sequential orchestration, aggregation and timestamps.
- `main`: argument parsing, batching and serialization.
- `tests/test_scoring.py`: reproducible offline checks of selected functions.
