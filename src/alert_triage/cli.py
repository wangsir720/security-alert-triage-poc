from __future__ import annotations

import argparse
from pathlib import Path

from .ingest import load_alerts, load_threat_intel
from .pipeline import (
    summarize_results,
    triage_alerts,
    write_html_report,
    write_json_report,
    write_markdown_report,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run alert triage and intelligence enrichment POC")
    parser.add_argument("--alerts", default="data/sample_alerts.jsonl")
    parser.add_argument("--intel", default="data/threat_intel.json")
    parser.add_argument("--output-dir", default="outputs")
    args = parser.parse_args()

    alerts = load_alerts(args.alerts)
    threat_intel = load_threat_intel(args.intel)
    results = triage_alerts(alerts, threat_intel)
    output_dir = Path(args.output_dir)
    write_json_report(results, output_dir / "latest.json")
    write_markdown_report(results, output_dir / "latest.md")
    write_html_report(results, output_dir / "latest.html")
    print(summarize_results(results))


if __name__ == "__main__":
    main()

