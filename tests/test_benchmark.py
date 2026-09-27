from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from alert_triage.benchmark import (
    run_benchmark,
    write_benchmark_alerts,
)


class BenchmarkTest(unittest.TestCase):
    def test_benchmark_reduces_false_positives(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            benchmark_path = Path(directory) / "benchmark.jsonl"
            write_benchmark_alerts(benchmark_path, 40)
            result = run_benchmark(
                benchmark_path,
                ROOT / "data" / "threat_intel.json",
            )

        self.assertEqual(result["alerts"], 40)
        self.assertGreater(
            result["baseline"]["false_positive_high"],
            result["enriched"]["false_positive_high"],
        )
        self.assertGreater(result["false_positive_reduction"], 0)
        self.assertEqual(result["enriched"]["high_recall"], 1.0)


if __name__ == "__main__":
    unittest.main()

