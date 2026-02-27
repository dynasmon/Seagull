from __future__ import annotations

from typing import Dict, Optional


TACTIC_LABELS: Dict[str, str] = {
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "command_and_control": "Command and Control",
    "exfiltration": "Exfiltration",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "impact": "Impact",
}


TECHNIQUES: Dict[str, str] = {
    # Brute force
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",

    # Scanning / discovery
    "T1046": "Network Service Scanning",
    "T1595": "Active Scanning",

    "T1018": "Remote System Discovery",
    # Remote services / lateral
    "T1021": "Remote Services",

    # Defense evasion / impair defenses
    "T1562": "Impair Defenses",

    # Command and control (generic)
    "T1071": "Application Layer Protocol",

    # DDoS / impact
    "T1498": "Network Denial of Service",
    "T1498.001": "Network Denial of Service: Direct Network Flood",
    "T1498.002": "Network Denial of Service: Reflection Amplification",

    # Valid accounts
    "T1078": "Valid Accounts",

    # Sudo / elevation control mechanisms
    "T1548.003": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",

    # Command and scripting interpreter
    "T1059": "Command and Scripting Interpreter",
}


def tactic_label(tactic: Optional[str]) -> str:
    t = str(tactic or "").strip().lower()
    return TACTIC_LABELS.get(t, tactic or "")


def technique_name(technique_id: Optional[str]) -> Optional[str]:
    tid = str(technique_id or "").strip()
    if not tid:
        return None
    return TECHNIQUES.get(tid)
