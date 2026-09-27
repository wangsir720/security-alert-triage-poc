from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Alert:
    id: str
    timestamp: str
    source: str
    severity: str
    title: str
    asset_criticality: str = "medium"
    src_ip: str = ""
    dst_ip: str = ""
    domain: str = ""
    url: str = ""
    file_hash: str = ""
    user: str = ""
    description: str = ""

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Alert":
        return cls(
            id=str(value.get("id", "")),
            timestamp=str(value.get("timestamp", "")),
            source=str(value.get("source", "")),
            severity=str(value.get("severity", "low")).lower(),
            title=str(value.get("title", "")),
            asset_criticality=str(value.get("asset_criticality", "medium")).lower(),
            src_ip=str(value.get("src_ip", "")),
            dst_ip=str(value.get("dst_ip", "")),
            domain=str(value.get("domain", "")),
            url=str(value.get("url", "")),
            file_hash=str(value.get("file_hash", "")),
            user=str(value.get("user", "")),
            description=str(value.get("description", "")),
        )


@dataclass(frozen=True)
class IntelMatch:
    indicator: str
    indicator_type: str
    verdict: str
    confidence: int
    tags: tuple[str, ...]
    source: str


@dataclass(frozen=True)
class TriagedAlert:
    alert: Alert
    indicators: tuple[str, ...]
    intel_matches: tuple[IntelMatch, ...]
    risk_score: int
    risk_level: str
    recommendations: tuple[str, ...]
    analyst_summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.alert.id,
            "timestamp": self.alert.timestamp,
            "source": self.alert.source,
            "severity": self.alert.severity,
            "title": self.alert.title,
            "asset_criticality": self.alert.asset_criticality,
            "indicators": list(self.indicators),
            "intel_matches": [
                {
                    "indicator": match.indicator,
                    "indicator_type": match.indicator_type,
                    "verdict": match.verdict,
                    "confidence": match.confidence,
                    "tags": list(match.tags),
                    "source": match.source,
                }
                for match in self.intel_matches
            ],
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "recommendations": list(self.recommendations),
            "analyst_summary": self.analyst_summary,
        }

