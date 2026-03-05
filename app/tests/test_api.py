from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

FIXTURES = Path(__file__).parent / "fixtures"


def _read_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _read_json(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_mitre_mapping_present():
    payload = {
        "source": "generic",
        "raw_logs": "Failed password for invalid user admin from 185.203.116.23 port 51122",
        "metadata": {"env": "test"},
    }
    r = client.post("/analyze", json=payload)
    assert r.status_code == 200
    data = r.json()

    assert "mapped_tactics" in data
    assert isinstance(data["mapped_tactics"], list)
    assert any(t.startswith("T1110") for t in data["mapped_tactics"])


def test_analyze_generic_log_fixture():
    raw = "Mar 04 12:01:02 host1 sshd[222]: Failed password for invalid user admin from 185.203.116.23 port 51122"
    payload = {"source": "generic", "raw_logs": raw, "metadata": {"env": "test"}}

    r = client.post("/analyze", json=payload)
    assert r.status_code == 200

    data = r.json()
    for key in ["title", "what_happened", "severity", "confidence", "recommended_steps", "executive_summary"]:
        assert key in data

    assert data["severity"] in ["low", "medium", "high", "critical"]
    assert 0.0 <= data["confidence"] <= 1.0
    assert isinstance(data["recommended_steps"], list)
    assert len(data["recommended_steps"]) >= 3


def test_analyze_powershell_fixture_includes_mitre():
    raw = _read_text("powershell_suspicious.log")
    payload = {"source": "windows", "raw_logs": raw, "metadata": {"env": "test"}}

    r = client.post("/analyze", json=payload)
    assert r.status_code == 200

    data = r.json()
    assert "mapped_tactics" in data
    assert isinstance(data["mapped_tactics"], list)
    assert any(t.startswith("T1059.001") for t in data["mapped_tactics"])
    assert any(t.startswith("T1027") for t in data["mapped_tactics"])


def test_analyze_cloudtrail_fixture_includes_mitre():
    raw = _read_json("cloudtrail_suspicious.json")
    payload = {"source": "cloudtrail", "raw_logs": raw, "metadata": {"env": "test"}}

    r = client.post("/analyze", json=payload)
    assert r.status_code == 200

    data = r.json()
    assert "mapped_tactics" in data
    assert isinstance(data["mapped_tactics"], list)
    assert any(t.startswith("T1098") for t in data["mapped_tactics"]) or any(
        t.startswith("T1078") for t in data["mapped_tactics"]
    )