"""
Forensic Engine browser connector API.

Deploy this file as a separate web service (for example, Render) and set
FORENSIC_API_URL in the Streamlit app and API_BASE_URL in the extension.
Evidence is short-lived and stored in process memory; configure a persistent,
authenticated store before production use.
"""
import os
import secrets
import time
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Forensic Engine Connector API", version="1.0.0")
API_KEY = os.environ.get("FORENSIC_CONNECTOR_KEY", "")
TTL_SECONDS = int(os.environ.get("EVIDENCE_TTL_SECONDS", "900"))
_store: dict[str, dict[str, Any]] = {}


class EvidencePayload(BaseModel):
    token: str = Field(min_length=20, max_length=128)
    start_date: str
    end_date: str
    records: list[dict[str, Any]] = Field(max_length=20000)


def check_key(x_connector_key: str | None):
    if not API_KEY:
        raise HTTPException(status_code=503, detail="Connector API key is not configured.")
    if not x_connector_key or not secrets.compare_digest(x_connector_key, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid connector key.")


@app.get("/health")
def health():
    return {"ok": True, "service": "forensic-connector-api"}


@app.post("/v1/evidence")
def receive_evidence(payload: EvidencePayload, x_connector_key: str | None = Header(default=None)):
    check_key(x_connector_key)
    if payload.start_date > payload.end_date:
        raise HTTPException(status_code=400, detail="Invalid date range.")
    if not payload.records:
        raise HTTPException(status_code=422, detail="No browser history records received.")
    now = time.time()
    for key in list(_store):
        if now - _store[key]["created_at"] > TTL_SECONDS:
            del _store[key]
    _store[payload.token] = {
        "created_at": now,
        "start_date": payload.start_date,
        "end_date": payload.end_date,
        "records": payload.records,
    }
    return {"ok": True, "count": len(payload.records), "token": payload.token}


@app.get("/v1/evidence/{token}")
def get_evidence(token: str, x_connector_key: str | None = Header(default=None)):
    check_key(x_connector_key)
    item = _store.get(token)
    if not item or time.time() - item["created_at"] > TTL_SECONDS:
        _store.pop(token, None)
        raise HTTPException(status_code=404, detail="Evidence not found or expired. Retrieve history again.")
    return {
        "start_date": item["start_date"],
        "end_date": item["end_date"],
        "records": item["records"],
        "count": len(item["records"]),
    }


@app.delete("/v1/evidence/{token}")
def delete_evidence(token: str, x_connector_key: str | None = Header(default=None)):
    check_key(x_connector_key)
    _store.pop(token, None)
    return {"ok": True}
