from __future__ import annotations

import json
from pathlib import Path

from .models import Alert


def load_alerts(path: str | Path) -> list[Alert]:
    alerts: list[Alert] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(Alert.from_dict(json.loads(line)))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}: {exc}") from exc
    return alerts


def load_threat_intel(path: str | Path) -> dict[str, dict]:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Threat intelligence file must contain a JSON object")
    return data

