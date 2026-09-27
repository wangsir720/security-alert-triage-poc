# Controlled Alert Triage Benchmark

## Method

- Dataset: controlled synthetic alerts with explicit ground truth.
- Baseline: severity-only routing.
- Enriched system: IOC enrichment, intelligence matching, risk scoring, and MITRE mapping.
- Analyst MTTI assumption: 180.0 seconds per alert.
- The MTTI number is an explicitly labeled estimate, not a human-subject measurement.

## Results

| Metric | Baseline | Enriched |
|---|---:|---:|
| High-risk true positives | 60 | 60 |
| High-risk false positives | 120 | 60 |
| High-risk precision | 33.3% | 50.0% |
| High-risk recall | 100.0% | 100.0% |

- False-positive reduction: **50.0%**
- Automated processing time per alert: **0.000009s**
- Confirmation time assumption: **60.0s per alert**
- Estimated MTTI per alert: **60.0s**
- Estimated MTTI reduction: **66.7%** (assumption-based)

## Boundary

This benchmark uses controlled synthetic data. Run the same harness with organization-approved data before making production claims.
