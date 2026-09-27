import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from alert_triage.benchmark import run_benchmark, write_benchmark_report


result = run_benchmark(
    ROOT / "data" / "benchmark_alerts.jsonl",
    ROOT / "data" / "threat_intel.json",
)
(ROOT / "outputs").mkdir(exist_ok=True)
(ROOT / "outputs" / "benchmark.json").write_text(
    json.dumps(result, ensure_ascii=False, indent=2),
    encoding="utf-8",
)
write_benchmark_report(result, ROOT / "outputs" / "benchmark.md")
print(
    {
        "alerts": result["alerts"],
        "false_positive_reduction": result["false_positive_reduction"],
        "estimated_mtti_reduction": result["estimated_mtti_reduction"],
        "automated_seconds_per_alert": result["automated_seconds_per_alert"],
    }
)


