from __future__ import annotations

from .models import Alert, IntelMatch


def extract_indicators(alert: Alert) -> tuple[str, ...]:
    indicators = []
    for value in (alert.src_ip, alert.dst_ip, alert.domain, alert.url, alert.file_hash):
        value = value.strip()
        if value and value not in indicators:
            indicators.append(value)
    return tuple(indicators)


def enrich_indicators(
    indicators: tuple[str, ...],
    threat_intel: dict[str, dict],
) -> tuple[IntelMatch, ...]:
    matches: list[IntelMatch] = []
    for indicator in indicators:
        record = threat_intel.get(indicator)
        if not record:
            continue
        matches.append(
            IntelMatch(
                indicator=indicator,
                indicator_type=str(record.get("type", "unknown")),
                verdict=str(record.get("verdict", "unknown")),
                confidence=int(record.get("confidence", 0)),
                tags=tuple(str(tag) for tag in record.get("tags", [])),
                source=str(record.get("source", "local-intel")),
            )
        )
    return tuple(matches)

