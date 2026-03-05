from __future__ import annotations

import json
import os
from typing import Any, Dict

from pydantic import ValidationError

from .schemas import IncidentReport


SYSTEM_PROMPT = """You are IncidentIQ, an AI Incident Response Copilot for SOC analysts.
You analyze security logs/signals and output a concise incident report.

Rules:
- Output MUST be valid JSON only (no markdown).
- Use severity: low | medium | high | critical
- Confidence must be 0.0 to 1.0
- recommended_steps must be a checklist of at least 3 items
- executive_summary should be 3–5 sentences, non-technical, leadership-friendly
- If unsure, say so and lower confidence.
"""


def _mock_response(signal_bundle: Dict[str, Any]) -> IncidentReport:
    return IncidentReport(
        title="Suspicious Activity Detected (Mock)",
        what_happened="IncidentIQ received logs and generated a mock analysis response (no LLM key configured).",
        severity="medium",
        confidence=0.55,
        indicators=[
            "Log volume appears elevated",
            "Potential authentication or execution behavior present (unconfirmed)",
        ],
        recommended_steps=[
            "Validate the alert by reviewing the raw logs and timeline.",
            "Check affected host/user accounts for abnormal activity.",
            "If malicious indicators are confirmed, isolate impacted systems and rotate credentials.",
        ],
        executive_summary=(
            "A potential security event was detected based on the submitted logs. "
            "At this stage, the evidence is not sufficient to confirm a specific attack type. "
            "Security staff should review the timeline and validate whether activity is benign or malicious. "
            "If confirmed, containment and credential hygiene steps are recommended."
        ),
        mapped_tactics=[],
        raw_signal=signal_bundle,
    )


def generate_incident_report(signal_bundle: Dict[str, Any]) -> IncidentReport:
    api_key = os.getenv("OPENAI_API_KEY")
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    if not api_key:
        return _mock_response(signal_bundle)

    from openai import OpenAI 

    client = OpenAI(api_key=api_key)

    user_prompt = {
        "task": "Analyze the signal bundle and generate an incident report JSON matching the schema.",
        "signal_bundle": signal_bundle,
        "output_schema": IncidentReport.model_json_schema(),
    }

    resp = client.chat.completions.create(
        model=model,
        temperature=0.0,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(user_prompt)},
        ],
    )

    content = resp.choices[0].message.content or "{}"

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return _mock_response(signal_bundle)

    try:
        return IncidentReport(**data)
    except ValidationError:
        return _mock_response(signal_bundle)