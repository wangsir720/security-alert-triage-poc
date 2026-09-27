from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from alert_triage.ingest import load_alerts, load_threat_intel
from alert_triage.pipeline import summarize_results, triage_alerts


class PipelineTest(unittest.TestCase):
    def test_pipeline_classifies_high_risk_alert(self) -> None:
        alerts = load_alerts(ROOT / "data" / "sample_alerts.jsonl")
        intel = load_threat_intel(ROOT / "data" / "threat_intel.json")
        results = triage_alerts(alerts, intel)
        by_id = {result.alert.id: result for result in results}

        self.assertEqual(by_id["ALT-001"].risk_level, "high")
        self.assertGreaterEqual(by_id["ALT-001"].risk_score, 70)
        self.assertIn("c2", by_id["ALT-001"].intel_matches[0].tags)
        self.assertEqual(by_id["ALT-004"].risk_level, "high")
        self.assertEqual(by_id["ALT-008"].risk_level, "low")

    def test_summary_counts(self) -> None:
        alerts = load_alerts(ROOT / "data" / "sample_alerts.jsonl")
        intel = load_threat_intel(ROOT / "data" / "threat_intel.json")
        summary = summarize_results(triage_alerts(alerts, intel))

        self.assertEqual(summary["alerts"], 8)
        self.assertEqual(summary["high"] + summary["medium"] + summary["low"], 8)
        self.assertGreater(summary["intel_match_rate"], 0)


if __name__ == "__main__":
    unittest.main()

