from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .pipeline import run_pipeline
from .schemas import AnalyzeRequest, IncidentReport
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="IncidentIQ API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten later for prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok", "service": "IncidentIQ"}


@app.post("/analyze", response_model=IncidentReport)
def analyze(req: AnalyzeRequest):
    return run_pipeline(raw_logs=req.raw_logs, source=req.source, metadata=req.metadata)