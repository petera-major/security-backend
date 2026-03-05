from __future__ import annotations
from typing import Any, Dict, List, Tuple

POWERSHELL_TECHNIQUES: List[Tuple[str, str]] = [
    ("T1059.001", "Command and Scripting Interpreter: PowerShell"),
    ("T1027", "Obfuscated/Compressed Files and Information"),
    ("T1140", "Deobfuscate/Decode Files or Information"),
]

CLOUDTRAIL_TECHNIQUES: List[Tuple[str, str]] = [
    ("T1078", "Valid Accounts"),
    ("T1098", "Account Manipulation"),
    ("T1087", "Account Discovery"),
    ("T1552", "Unsecured Credentials"),
    ("T1548", "Abuse Elevation Control Mechanism"),
]

GENERIC_TECHNIQUES: List[Tuple[str, str]] = [
    ("T1562", "Impair Defenses"),
    ("T1046", "Network Service Discovery"),
    ("T1110", "Brute Force"),
]

def map_mitre_from_signal(signal_bundle: Dict[str, Any]) -> List[str]:
    """
    Deterministic mapping based on detector + keywords in normalized events.
    Returns a list of strings like: "T1059.001 - Command and Scripting Interpreter: PowerShell"
    """
    detector = (signal_bundle.get("detector") or "").lower()
    primary = (signal_bundle.get("primary_signal") or "").lower()

    events = signal_bundle.get("normalized_events") or []
    text_blob = " ".join([str(e).lower() for e in events]) + " " + primary

    mapped: List[Tuple[str, str]] = []

    if "powershell" in detector or "powershell" in text_blob:
        mapped.extend(POWERSHELL_TECHNIQUES)

        if "encodedcommand" in text_blob or "-enc" in text_blob or "frombase64string" in text_blob:
            mapped.append(("T1027", "Obfuscated/Compressed Files and Information"))
            mapped.append(("T1140", "Deobfuscate/Decode Files or Information"))

    if "cloudtrail" in detector or "eventname" in text_blob or "awscloudtrail" in text_blob:
        mapped.extend(CLOUDTRAIL_TECHNIQUES)

        if "createaccesskey" in text_blob or "updateaccesskey" in text_blob:
            mapped.append(("T1098", "Account Manipulation"))

        if "attachuserpolicy" in text_blob or "putuserpolicy" in text_blob or "attachgrouppolicy" in text_blob:
            mapped.append(("T1548", "Abuse Elevation Control Mechanism"))

        if "consolelogin" in text_blob and ("failure" in text_blob or "failed" in text_blob):
            mapped.append(("T1078", "Valid Accounts"))

    if "failed password" in text_blob or "failed login" in text_blob or "invalid user" in text_blob:
        mapped.append(("T1110", "Brute Force"))

    seen = set()
    out: List[str] = []
    for tid, name in mapped:
        key = f"{tid}-{name}"
        if key not in seen:
            seen.add(key)
            out.append(f"{tid} - {name}")

    return out