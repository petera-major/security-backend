from __future__ import annotations

from typing import Annotated, Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high", "critical"]


class AnalyzeRequest(BaseModel):
    source: Optional[str] = Field(default=None, description="Optional source label like 'windows', 'cloudtrail'")
    raw_logs: Any = Field(..., description="Raw logs as string or JSON object/list")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Optional extra context (env, org, etc.)")


class Indicator(BaseModel):
    type: str = Field(..., description="e.g., 'ip', 'user', 'process', 'api_call'")
    value: str = Field(..., description="Value of indicator")
    note: Optional[str] = None


class IncidentReport(BaseModel):
    title: str
    what_happened: str
    severity: Severity
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = 0.7

    indicators: List[str] = Field(default_factory=list)
    recommended_steps: Annotated[List[str], Field(min_length=3)] = Field(default_factory=list)

    executive_summary: str
    mapped_tactics: List[str] = Field(default_factory=list, description="Optional MITRE ATT&CK tactics/techniques")
    raw_signal: Dict[str, Any] = Field(default_factory=dict, description="Normalized + enriched signal bundle")