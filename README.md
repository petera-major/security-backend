# IncidentIQ Backend API

Tis backend powers the AI analysis engine for IncidentIQ.

It ingests security logs, runs detection pipelines, and uses an LLM to generate structured incident intelligence reports to assist SOC teams.

## Tech Stack

- Python
- FastAPI
- Pydantic
- LLM integration
- Log detection pipeline

## Core Components

main.py
FastAPI server and API routes.

pipeline.py
Security analysis pipeline that processes logs and runs detection modules.

llm.py
LLM interface used to generate incident explanations and summaries.

schemas.py
Pydantic schemas defining request and response structures.

detectors/
Rule-based detection modules for identifying suspicious activity.

## API Endpoint

POST /analyze

Analyzes security logs and returns an incident intelligence report.

Example request:

{
  "source": "siem",
  "raw_logs": "...",
  "metadata": {}
}

Example response:

{
  "severity": "high",
  "confidence": 0.86,
  "mitre_techniques": ["T1059.001", "T1027"],
  "summary": "...",
  "recommended_actions": [...]
}

## Running the API

Install dependencies:

pip install -r requirements.txt

Start the server:

uvicorn app.main:app --reload
