from __future__ import annotations

from typing import Any, Dict, Optional

from .detectors.base import BaseDetector
from .llm import generate_incident_report
from .schemas import IncidentReport
from .mitre import map_mitre_from_signal

# from .detectors.powershell import PowerShellDetector
# from .detectors.cloudtrail import CloudTrailDetector

DETECTORS = [
    # PowerShellDetector(),
    # CloudTrailDetector(),
    BaseDetector(),  
]


def run_pipeline(raw_logs: Any, source: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> IncidentReport:
    metadata = metadata or {}

    chosen = None
    for det in DETECTORS:
        if det.can_handle(raw_logs, source=source):
            chosen = det
            break

    if chosen is None:
        chosen = BaseDetector()

    detection = chosen.normalize(raw_logs, source=source)

    signal_bundle: Dict[str, Any] = {
        "source": source or "unknown",
        "metadata": metadata,
        "detector": detection.detector,
        "primary_signal": detection.primary_signal,
        "key_fields": detection.key_fields,
        "normalized_events": detection.normalized_events,
        "notes": detection.notes,
    }

    mapped = map_mitre_from_signal(signal_bundle)
    signal_bundle["mitre_mapping"] = mapped

    report = generate_incident_report(signal_bundle)

    report.raw_signal = signal_bundle
    report.mapped_tactics = mapped
    return report
