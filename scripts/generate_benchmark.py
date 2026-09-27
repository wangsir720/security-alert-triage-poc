from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from alert_triage.benchmark import write_benchmark_alerts


write_benchmark_alerts(ROOT / "data" / "benchmark_alerts.jsonl", 240)
print("benchmark alerts written")

