from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from alert_triage.connectors import suricata_eve_to_alert, wazuh_event_to_alert
from alert_triage.mitre import map_matches_to_attack
from alert_triage.models import IntelMatch


class ConnectorAndMitreTest(unittest.TestCase):
    def test_suricata_conversion(self) -> None:
        alert = suricata_eve_to_alert(
            {
                "timestamp": "2026-09-27T10:00:00+08:00",
                "src_ip": "10.0.0.10",
                "dest_ip": "45.88.90.12",
                "alert": {
                    "signature": "Known C2 endpoint",
                    "severity": 1,
                },
            }
        )
        self.assertEqual(alert.source, "Suricata")
        self.assertEqual(alert.severity, "high")
        self.assertEqual(alert.dst_ip, "45.88.90.12")

    def test_wazuh_conversion(self) -> None:
        alert = wazuh_event_to_alert(
            {
                "timestamp": "2026-09-27T10:01:00+08:00",
                "rule": {"level": 12, "description": "Credential dumping"},
                "data": {"dstuser": "admin-local"},
            }
        )
        self.assertEqual(alert.source, "Wazuh")
        self.assertEqual(alert.severity, "high")
        self.assertEqual(alert.user, "admin-local")

    def test_mitre_mapping(self) -> None:
        techniques = map_matches_to_attack(
            (
                IntelMatch(
                    indicator="45.88.90.12",
                    indicator_type="ip",
                    verdict="malicious",
                    confidence=95,
                    tags=("c2",),
                    source="test",
                ),
            )
        )
        self.assertEqual(techniques[0]["id"], "T1071")


if __name__ == "__main__":
    unittest.main()

