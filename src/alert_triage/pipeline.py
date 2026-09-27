from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .enrichment import enrich_indicators, extract_indicators
from .mitre import map_matches_to_attack
from .models import Alert, TriagedAlert
from .scoring import build_recommendations, build_summary, risk_level, score_alert


def triage_alert(alert: Alert, threat_intel: dict[str, dict]) -> TriagedAlert:
    indicators = extract_indicators(alert)
    matches = enrich_indicators(indicators, threat_intel)
    score = score_alert(alert, matches)
    level = risk_level(score)
    recommendations = build_recommendations(alert, matches)
    summary = build_summary(alert, score, level, matches)
    return TriagedAlert(
        alert=alert,
        indicators=indicators,
        intel_matches=matches,
        risk_score=score,
        risk_level=level,
        recommendations=recommendations,
        analyst_summary=summary,
    )


def triage_alerts(alerts: list[Alert], threat_intel: dict[str, dict]) -> list[TriagedAlert]:
    return [triage_alert(alert, threat_intel) for alert in alerts]


def summarize_results(results: list[TriagedAlert]) -> dict[str, Any]:
    counts = Counter(result.risk_level for result in results)
    matched = sum(1 for result in results if result.intel_matches)
    return {
        "alerts": len(results),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "intel_matched": matched,
        "intel_match_rate": round(matched / len(results), 3) if results else 0,
    }


def write_json_report(results: list[TriagedAlert], output: str | Path) -> None:
    alerts = []
    for result in results:
        record = result.to_dict()
        record["mitre_techniques"] = list(map_matches_to_attack(result.intel_matches))
        alerts.append(record)
    payload = {
        "summary": summarize_results(results),
        "alerts": alerts,
    }
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def write_markdown_report(results: list[TriagedAlert], output: str | Path) -> None:
    summary = summarize_results(results)
    lines = [
        "# Security Alert Triage Report",
        "",
        "## Summary",
        "",
        f"- Alerts: {summary['alerts']}",
        f"- High: {summary['high']}",
        f"- Medium: {summary['medium']}",
        f"- Low: {summary['low']}",
        f"- IOC matched: {summary['intel_matched']}",
        f"- IOC match rate: {summary['intel_match_rate']:.1%}",
        "",
        "## Alerts",
        "",
    ]
    for result in sorted(results, key=lambda item: item.risk_score, reverse=True):
        lines.extend(
            [
                f"### {result.alert.id} · {result.alert.title}",
                "",
                f"- Risk: **{result.risk_score}/100 ({result.risk_level})**",
                f"- Source: {result.alert.source}",
                f"- Asset: {result.alert.asset_criticality}",
                f"- Indicators: {', '.join(result.indicators) or 'none'}",
                f"- MITRE ATT&CK: {', '.join(item['id'] for item in map_matches_to_attack(result.intel_matches)) or 'none'}",
                f"- Summary: {result.analyst_summary}",
                "- Recommendations:",
            ]
        )
        lines.extend(f"  - {item}" for item in result.recommendations)
        lines.append("")
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text("\n".join(lines), encoding="utf-8")


def write_html_report(results: list[TriagedAlert], output: str | Path) -> None:
    summary = summarize_results(results)
    rows = []
    for result in sorted(results, key=lambda item: item.risk_score, reverse=True):
        rows.append(
            "<tr>"
            f"<td>{result.alert.id}</td>"
            f"<td>{result.alert.title}</td>"
            f"<td>{result.alert.source}</td>"
            f"<td>{result.risk_score}</td>"
            f"<td>{result.risk_level}</td>"
            f"<td>{', '.join(result.indicators)}</td>"
            "</tr>"
        )
    html = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>Security Alert Triage POC</title>
  <style>
    body {{ font-family: sans-serif; margin: 32px; color: #1f2937; }}
    .cards {{ display: flex; gap: 12px; margin-bottom: 24px; }}
    .card {{ background: #eff6ff; border: 1px solid #bfdbfe; padding: 12px 18px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #d1d5db; padding: 8px; text-align: left; }}
    th {{ background: #f3f4f6; }}
  </style>
</head>
<body>
  <h1>Security Alert Triage POC</h1>
  <div class="cards">
    <div class="card"><strong>{summary['alerts']}</strong><br>Alerts</div>
    <div class="card"><strong>{summary['high']}</strong><br>High</div>
    <div class="card"><strong>{summary['medium']}</strong><br>Medium</div>
    <div class="card"><strong>{summary['intel_match_rate']:.1%}</strong><br>IOC match rate</div>
  </div>
  <table>
    <thead><tr><th>ID</th><th>Title</th><th>Source</th><th>Score</th><th>Level</th><th>Indicators</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</body>
</html>
"""
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(html, encoding="utf-8")

