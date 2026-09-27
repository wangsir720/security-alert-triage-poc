from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .ingest import load_threat_intel
from .models import Alert
from .pipeline import triage_alert


def generate_benchmark_alerts(count: int = 240) -> list[dict[str, Any]]:
    if count < 4:
        raise ValueError("count must be at least 4")

    groups = (
        {
            "kind": "actionable",
            "weight": 1,
            "severity": "high",
            "asset_criticality": "high",
            "src_ip": "45.88.90.12",
            "domain": "",
            "tags": ["c2"],
            "ground_truth_actionable": True,
        },
        {
            "kind": "high-severity-but-benign",
            "weight": 1,
            "severity": "high",
            "asset_criticality": "medium",
            "src_ip": "10.10.10.10",
            "domain": "",
            "tags": [],
            "ground_truth_actionable": False,
        },
        {
            "kind": "critical-asset-hard-case",
            "weight": 1,
            "severity": "critical",
            "asset_criticality": "critical",
            "src_ip": "10.10.20.20",
            "domain": "",
            "tags": [],
            "ground_truth_actionable": False,
        },
        {
            "kind": "benign-low-signal",
            "weight": 1,
            "severity": "low",
            "asset_criticality": "low",
            "src_ip": "203.0.113.9",
            "domain": "",
            "tags": [],
            "ground_truth_actionable": False,
        },
    )
    alerts: list[dict[str, Any]] = []
    for index in range(count):
        group = groups[index % len(groups)]
        alerts.append(
            {
                "id": f"BENCH-{index + 1:04d}",
                "timestamp": f"2026-09-27T10:{index % 60:02d}:00+08:00",
                "source": "Benchmark",
                "severity": group["severity"],
                "title": f"Benchmark alert {group['kind']}",
                "asset_criticality": group["asset_criticality"],
                "src_ip": group["src_ip"],
                "dst_ip": "10.0.0.1",
                "domain": group["domain"],
                "file_hash": "",
                "user": "benchmark",
                "description": "Controlled benchmark alert.",
                "ground_truth_actionable": group["ground_truth_actionable"],
            }
        )
    return alerts


def write_benchmark_alerts(path: str | Path, count: int = 240) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for alert in generate_benchmark_alerts(count):
            handle.write(json.dumps(alert, ensure_ascii=False) + "\n")


def _baseline_prediction(alert: Alert) -> str:
    if alert.severity in {"high", "critical"}:
        return "high"
    if alert.severity == "medium":
        return "medium"
    return "low"


def _safe_rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def run_benchmark(
    benchmark_path: str | Path,
    intel_path: str | Path,
    manual_seconds_per_alert: float = 180.0,
    confirmation_seconds_per_alert: float = 60.0,
) -> dict[str, Any]:
    threat_intel = load_threat_intel(intel_path)
    rows = [
        json.loads(line)
        for line in Path(benchmark_path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    baseline_tp = baseline_fp = 0
    enriched_tp = enriched_fp = 0
    enriched_actionable = 0
    started = time.perf_counter()
    details = []

    for row in rows:
        alert = Alert.from_dict(row)
        baseline = _baseline_prediction(alert)
        result = triage_alert(alert, threat_intel)
        expected = bool(row["ground_truth_actionable"])

        baseline_high = baseline == "high"
        enriched_high = result.risk_level == "high"
        baseline_tp += int(baseline_high and expected)
        baseline_fp += int(baseline_high and not expected)
        enriched_tp += int(enriched_high and expected)
        enriched_fp += int(enriched_high and not expected)
        enriched_actionable += int(enriched_high and expected)
        details.append(
            {
                "id": alert.id,
                "expected_actionable": expected,
                "baseline_level": baseline,
                "enriched_level": result.risk_level,
                "enriched_score": result.risk_score,
                "intel_matched": bool(result.intel_matches),
            }
        )

    elapsed = time.perf_counter() - started
    actual_actionable = sum(1 for row in rows if row["ground_truth_actionable"])
    baseline_false_positive_reduction = (
        (baseline_fp - enriched_fp) / baseline_fp if baseline_fp else 0.0
    )
    automated_seconds_per_alert = elapsed / len(rows) if rows else 0.0
    estimated_mtti_seconds_per_alert = (
        automated_seconds_per_alert + confirmation_seconds_per_alert
    )
    estimated_mtti_reduction = (
        1 - estimated_mtti_seconds_per_alert / manual_seconds_per_alert
        if manual_seconds_per_alert
        else 0.0
    )

    return {
        "method": "controlled synthetic alert benchmark",
        "alerts": len(rows),
        "actual_actionable": actual_actionable,
        "baseline": {
            "true_positive_high": baseline_tp,
            "false_positive_high": baseline_fp,
            "high_precision": _safe_rate(baseline_tp, baseline_tp + baseline_fp),
            "high_recall": _safe_rate(baseline_tp, actual_actionable),
        },
        "enriched": {
            "true_positive_high": enriched_tp,
            "false_positive_high": enriched_fp,
            "high_precision": _safe_rate(enriched_tp, enriched_tp + enriched_fp),
            "high_recall": _safe_rate(enriched_tp, actual_actionable),
        },
        "false_positive_reduction": round(baseline_false_positive_reduction, 4),
        "system_elapsed_seconds": round(elapsed, 6),
        "automated_seconds_per_alert": round(automated_seconds_per_alert, 6),
        "confirmation_seconds_per_alert_assumption": confirmation_seconds_per_alert,
        "estimated_mtti_seconds_per_alert": round(estimated_mtti_seconds_per_alert, 6),
        "manual_seconds_per_alert_assumption": manual_seconds_per_alert,
        "estimated_mtti_reduction": round(estimated_mtti_reduction, 4),
        "details": details,
    }


def write_benchmark_report(result: dict[str, Any], output: str | Path) -> None:
    lines = [
        "# Controlled Alert Triage Benchmark",
        "",
        "## Method",
        "",
        "- Dataset: controlled synthetic alerts with explicit ground truth.",
        "- Baseline: severity-only routing.",
        "- Enriched system: IOC enrichment, intelligence matching, risk scoring, and MITRE mapping.",
        f"- Analyst MTTI assumption: {result['manual_seconds_per_alert_assumption']} seconds per alert.",
        "- The MTTI number is an explicitly labeled estimate, not a human-subject measurement.",
        "",
        "## Results",
        "",
        "| Metric | Baseline | Enriched |",
        "|---|---:|---:|",
        f"| High-risk true positives | {result['baseline']['true_positive_high']} | {result['enriched']['true_positive_high']} |",
        f"| High-risk false positives | {result['baseline']['false_positive_high']} | {result['enriched']['false_positive_high']} |",
        f"| High-risk precision | {result['baseline']['high_precision']:.1%} | {result['enriched']['high_precision']:.1%} |",
        f"| High-risk recall | {result['baseline']['high_recall']:.1%} | {result['enriched']['high_recall']:.1%} |",
        "",
        f"- False-positive reduction: **{result['false_positive_reduction']:.1%}**",
        f"- Automated processing time per alert: **{result['automated_seconds_per_alert']:.6f}s**",
        f"- Confirmation time assumption: **{result['confirmation_seconds_per_alert_assumption']:.1f}s per alert**",
        f"- Estimated MTTI per alert: **{result['estimated_mtti_seconds_per_alert']:.1f}s**",
        f"- Estimated MTTI reduction: **{result['estimated_mtti_reduction']:.1%}** (assumption-based)",
        "",
        "## Boundary",
        "",
        "This benchmark uses controlled synthetic data. Run the same harness with organization-approved data before making production claims.",
    ]
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text("\n".join(lines) + "\n", encoding="utf-8")

