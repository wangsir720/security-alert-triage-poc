from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Alert


def suricata_eve_to_alert(event: dict[str, Any], index: int = 1) -> Alert:
    src_ip = str(event.get("src_ip", ""))
    dst_ip = str(event.get("dest_ip", ""))
    signature = str(event.get("alert", {}).get("signature", "Suricata alert"))
    severity_number = int(event.get("alert", {}).get("severity", 3))
    severity = {1: "high", 2: "medium", 3: "low"}.get(severity_number, "low")
    return Alert(
        id=f"EVE-{index:04d}",
        timestamp=str(event.get("timestamp", "")),
        source="Suricata",
        severity=severity,
        title=signature,
        asset_criticality="medium",
        src_ip=src_ip,
        dst_ip=dst_ip,
        domain=str(event.get("dns", {}).get("rrname", "")),
        url=str(event.get("http", {}).get("url", "")),
        description="Converted from Suricata EVE JSON.",
    )


def wazuh_event_to_alert(event: dict[str, Any], index: int = 1) -> Alert:
    rule = event.get("rule", {})
    data = event.get("data", {})
    rule_level = int(rule.get("level", 0))
    severity = "high" if rule_level >= 10 else "medium" if rule_level >= 7 else "low"
    return Alert(
        id=str(event.get("id", f"WAZUH-{index:04d}")),
        timestamp=str(event.get("timestamp", "")),
        source="Wazuh",
        severity=severity,
        title=str(rule.get("description", "Wazuh alert")),
        asset_criticality="high" if rule_level >= 10 else "medium",
        src_ip=str(data.get("srcip", "")),
        dst_ip=str(data.get("dstip", "")),
        file_hash=str(data.get("md5", "")),
        user=str(data.get("dstuser", "")),
        description=str(rule.get("description", "")),
    )


def convert_eve_file(path: str | Path, output: str | Path) -> int:
    count = 0
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open("r", encoding="utf-8") as source, output_path.open(
        "w", encoding="utf-8"
    ) as destination:
        for line in source:
            line = line.strip()
            if not line:
                continue
            count += 1
            alert = suricata_eve_to_alert(json.loads(line), count)
            destination.write(json.dumps(alert.__dict__, ensure_ascii=False) + "\n")
    return count

