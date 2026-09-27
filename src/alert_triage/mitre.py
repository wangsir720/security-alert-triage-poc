from __future__ import annotations

from .models import IntelMatch


TAG_TO_ATTACK = {
    "phishing": ("T1566", "Phishing"),
    "c2": ("T1071", "Application Layer Protocol"),
    "credential-access": ("T1003", "OS Credential Dumping"),
    "scanning": ("T1046", "Network Service Discovery"),
    "ransomware": ("T1486", "Data Encrypted for Impact"),
    "persistence": ("T1547", "Boot or Logon Autostart Execution"),
    "bruteforce": ("T1110", "Brute Force"),
}


def map_matches_to_attack(matches: tuple[IntelMatch, ...]) -> tuple[dict[str, str], ...]:
    techniques = {}
    for match in matches:
        for tag in match.tags:
            mapped = TAG_TO_ATTACK.get(tag)
            if mapped:
                technique_id, technique_name = mapped
                techniques[technique_id] = technique_name
    return tuple(
        {"id": technique_id, "name": technique_name}
        for technique_id, technique_name in sorted(techniques.items())
    )

