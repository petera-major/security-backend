from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DetectionResult:
    detector: str
    primary_signal: str
    normalized_events: List[Dict[str, Any]] = field(default_factory=list)
    key_fields: Dict[str, Any] = field(default_factory=dict)
    notes: Optional[str] = None


class BaseDetector:
    name: str = "base"

    def can_handle(self, raw_logs: Any, source: Optional[str] = None) -> bool:
        return True

    def normalize(self, raw_logs: Any, source: Optional[str] = None) -> DetectionResult:
        if isinstance(raw_logs, (dict, list)):
            preview = str(raw_logs)[:400]
        else:
            preview = str(raw_logs)[:400]

        return DetectionResult(
            detector=self.name,
            primary_signal="Generic log analysis (no specific detector matched).",
            normalized_events=[{"raw_preview": preview}],
            key_fields={"source": source or "unknown"},
            notes="Using generic detector. Add specialized detectors for PowerShell / CloudTrail next.",
        )