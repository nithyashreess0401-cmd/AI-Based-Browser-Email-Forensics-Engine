"""Short-lived token-based browser evidence connector."""
import os, secrets, time
from typing import Any
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Forensic Engine Connector API", version="1.1.0")
API_KEY = os.environ.get("FORENSIC_CONNECTOR_KEY", "")
TTL_SECONDS = int(os.environ.get("EVIDENCE_TTL_SECONDS", "900"))
_store: dict[str, dict[str, Any]] = {}

class SessionPayload(BaseModel):
    start_date: str
    end_date: str

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

@app.post("/v1/sessions")
def create_session(payload: SessionPayload, x_connector_key: str | None = Header(default=None)):
    check_key(x_connector_key)
    if payload.start_date > payload.end_date:
        raise HTTPException(status_code=400, detail="Invalid date range.")
    token = secrets.token_urlsafe(32)
    _store[token] = {"created_at": time.time(), "start_date": payload.start_date,
                     "end_date": payload.end_date, "records": None}
    return {"token": token, "expires_in_seconds": TTL_SECONDS,
            "start_date": payload.start_date, "end_date": payload.end_date}

@app.post("/v1/evidence")
def receive_evidence(payload: EvidencePayload):
    item = _store.get(payload.token)
    if not item or time.time() - item["created_at"] > TTL_SECONDS:
        _store.pop(payload.token, None)
        raise HTTPException(status_code=404, detail="Session token expired. Create a new session in Streamlit.")
    if item["start_date"] != payload.start_date or item["end_date"] != payload.end_date:
        raise HTTPException(status_code=400, detail="Dates do not match the Streamlit session.")
    if not payload.records:
        raise HTTPException(status_code=422, detail="No browser history records received.")
    item["records"] = payload.records
    item["uploaded_at"] = time.time()
    return {"ok": True, "count": len(payload.records)}

@app.get("/v1/evidence/{token}")
def get_evidence(token: str, x_connector_key: str | None = Header(default=None)):
    check_key(x_connector_key)
    item = _store.get(token)
    if not item or time.time() - item["created_at"] > TTL_SECONDS:
        _store.pop(token, None)
        raise HTTPException(status_code=404, detail="Session expired. Create a new session and retrieve history again.")
    if item.get("records") is None:
        raise HTTPException(status_code=404, detail="Waiting for Chrome extension to send history.")
    return {"start_date": item["start_date"], "end_date": item["end_date"],
            "records": item["records"], "count": len(item["records"])}

@app.delete("/v1/evidence/{token}")
def delete_evidence(token: str, x_connector_key: str | None = Header(default=None)):
    check_key(x_connector_key)
    _store.pop(token, None)
    return {"ok": True}
