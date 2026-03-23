"""MITRE ATT&CK constants — tactics and their IDs."""

TACTIC_IDS = {
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Exfiltration": "TA0010",
    "Command and Control": "TA0011",
}

MITRE_TACTICS = list(TACTIC_IDS.keys())

TACTIC_ICONS = {
    "Initial Access": "🚪",
    "Execution": "⚙",
    "Persistence": "📌",
    "Defense Evasion": "🛡",
    "Credential Access": "🔑",
    "Discovery": "🔭",
    "Lateral Movement": "↔",
    "Command and Control": "📡",
    "Exfiltration": "📤",
}


def build_threat_block(tactic: str, tech_id: str, tech_name: str) -> list:
    """Build the MITRE ATT&CK threat mapping block for Kibana rules."""
    tid = TACTIC_IDS.get(tactic, "TA0001")
    base_id = tech_id.split(".")[0]
    subtechniques = []

    if "." in tech_id:
        ref_id = tech_id.replace(".", "/")
        subtechniques = [{
            "id": tech_id,
            "name": tech_name,
            "reference": f"https://attack.mitre.org/techniques/{ref_id}/",
        }]

    return [{
        "framework": "MITRE ATT&CK",
        "tactic": {
            "id": tid,
            "name": tactic,
            "reference": f"https://attack.mitre.org/tactics/{tid}/",
        },
        "technique": [{
            "id": base_id,
            "name": tech_name.split(":")[0].strip(),
            "reference": f"https://attack.mitre.org/techniques/{base_id}/",
            "subtechnique": subtechniques,
        }],
    }]
