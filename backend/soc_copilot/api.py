from __future__ import annotations

import json
import logging
import time
from typing import Any, Iterator

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from . import __version__
from .agent import Investigator
from .config import get_settings
from .evals import run_suite
from .llm import select_backend
from .pii import PiiMasker
from .rag import KnowledgeBase
from .store import DataStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

settings = get_settings()
store = DataStore()
kb = KnowledgeBase(store, settings)
backend = select_backend(settings)
reports: dict[str, dict[str, Any]] = {}

app = FastAPI(title="SOC Copilot API", version=__version__)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["*"], allow_headers=["*"])


def _alert_row(a: dict[str, Any]) -> dict[str, Any]:
    r = reports.get(a["id"])
    return {**a, "status": "investigated" if r else a["status"],
            "ai_verdict": r["verdict"] if r else None, "ai_severity": r["severity"] if r else None}


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "version": __version__, "offline": True,
            "llm": {"backend": backend.name, "model": backend.model},
            "knowledge": kb.info(), "events": len(store.events), "alerts": len(store.alerts)}


@app.get("/api/alerts")
def list_alerts() -> list[dict[str, Any]]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted((_alert_row(a) for a in store.alerts), key=lambda a: (order.get(a["severity"], 9), a["created_at"]))


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str) -> dict[str, Any]:
    a = store.alert(alert_id)
    if not a:
        raise HTTPException(404, "alert not found")
    return {**_alert_row(a), "evidence": [store.event(r).to_dict() for r in a.get("evidence_refs", []) if store.event(r)],
            "report": reports.get(alert_id)}


def _investigator(guardrails: bool) -> Investigator:
    return Investigator(store, kb, backend, settings, guardrails=guardrails)


@app.post("/api/alerts/{alert_id}/investigate")
def investigate(alert_id: str, guardrails: bool = True) -> dict[str, Any]:
    if not store.alert(alert_id):
        raise HTTPException(404, "alert not found")
    report = _investigator(guardrails).run(alert_id)
    if guardrails:
        reports[alert_id] = report
    return report


@app.post("/api/alerts/{alert_id}/investigate/stream")
def investigate_stream(alert_id: str, guardrails: bool = True,
                       pace_ms: int = Query(0, ge=0, le=2000)) -> StreamingResponse:
    if not store.alert(alert_id):
        raise HTTPException(404, "alert not found")

    def gen() -> Iterator[bytes]:
        try:
            for ev in _investigator(guardrails).run_iter(alert_id):
                if ev["type"] == "report" and guardrails:
                    reports[alert_id] = ev["report"]
                if pace_ms and ev["type"] in ("tool_result", "phase"):
                    time.sleep(pace_ms / 1000)
                yield (json.dumps(ev, default=str) + "\n").encode()
        except Exception as exc:  # surface failures to the UI instead of a broken stream
            logging.exception("investigation failed")
            yield (json.dumps({"type": "error", "fatal": True, "message": str(exc)}) + "\n").encode()

    return StreamingResponse(gen(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/reports/{alert_id}")
def get_report(alert_id: str) -> dict[str, Any]:
    if alert_id not in reports:
        raise HTTPException(404, "no report yet")
    return reports[alert_id]


@app.get("/api/knowledge")
def knowledge() -> dict[str, Any]:
    return {**kb.info(), "documents": [{k: v for k, v in d.items() if k != "path"} for d in kb.docs.values()]}


@app.get("/api/knowledge/search")
def knowledge_search(q: str = Query(..., min_length=2, max_length=300), k: int = Query(5, ge=1, le=10)) -> dict[str, Any]:
    return kb.search(q, k=k)


class PiiRequest(BaseModel):
    text: str


@app.post("/api/pii/preview")
def pii_preview(req: PiiRequest) -> dict[str, Any]:
    m = PiiMasker(store.identities)
    return {"masked": m.mask_text(req.text[:20000]), "summary": m.summary()}


@app.post("/api/evals/run")
def evals_run() -> dict[str, Any]:
    return run_suite()
