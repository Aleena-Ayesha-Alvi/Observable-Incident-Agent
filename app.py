import json
from fastapi import Depends, FastAPI, HTTPException, Response
from sqlalchemy.orm import Session
from database import Base, engine, get_db
from models import IncidentRun, ReceiptRecord
from state_machine import initial_run, validate_payload
from receipts import apply_receipt
from utils import canonical, digest, redact

Base.metadata.create_all(bind=engine)
# Upgrade the starter project's original four-column SQLite table in place.
with engine.begin() as connection:
    cols = {row[1] for row in connection.exec_driver_sql("PRAGMA table_info(incident_runs)")}
    if "request_hash" not in cols:
        connection.exec_driver_sql("ALTER TABLE incident_runs ADD COLUMN request_hash VARCHAR")
app = FastAPI(title="Observable Incident Agent", version="2.0")

def conflict(detail): raise HTTPException(409, detail=detail)
def stored_run(row): return json.loads(row.response_json)
def stored_response(row): return Response(content=row.response_json, media_type="application/json")
def save_run(db, row, run): row.status = run["status"]; row.response_json = canonical(run); db.add(row); db.commit()

@app.get("/")
def home(): return {"status": "running"}

@app.post("/v2/incidents")
def create_incident(payload: dict, db: Session = Depends(get_db)):
    try:
        # Validate before consulting persistence.  Otherwise a malformed request
        # can be misreported as a replay conflict merely because its runId exists.
        validate_payload(payload)
        safe = redact(payload)
        request_hash = digest(payload)
        run_id = payload["runId"]
        existing = db.query(IncidentRun).filter(IncidentRun.run_id == run_id).first()
        if existing:
            if existing.request_hash == request_hash:
                return stored_response(existing)
            conflict("runId replay has changed content")
        run = initial_run(payload)
        row = IncidentRun(run_id=run_id, status=run["status"], request_json=canonical(safe), response_json=canonical(run), request_hash=request_hash)
        db.add(row)
        db.commit()
        return stored_response(row)
    except LookupError as exc:
        raise HTTPException(400, detail=str(exc))
    except ValueError as exc: raise HTTPException(400, detail=str(exc))

@app.get("/v2/incidents/{runId}")
def get_incident(runId: str, db: Session = Depends(get_db)):
    row = db.query(IncidentRun).filter(IncidentRun.run_id == runId).first()
    if not row: raise HTTPException(404, detail="Run not found")
    return stored_response(row)

@app.post("/v2/incidents/{runId}/receipts")
def receipt(runId: str, payload: dict, db: Session = Depends(get_db)):
    row = db.query(IncidentRun).filter(IncidentRun.run_id == runId).first()
    if not row: raise HTTPException(404, detail="Run not found")
    safe = redact(payload); rid = safe.get("receiptId")
    if not rid: raise HTTPException(400, detail="receiptId is required")
    # A one-way whole-request fingerprint preserves replay semantics even when
    # only a sensitive field changed, without persisting that field itself.
    h = digest(payload); old = db.query(ReceiptRecord).filter(ReceiptRecord.run_id == runId, ReceiptRecord.receipt_id == rid).first()
    if old:
        if old.receipt_hash == h: return json.loads(old.response_json)
        conflict("receiptId replay has changed content")
    try:
        run = stored_run(row); result = apply_receipt(run, payload); save_run(db, row, run)
        db.add(ReceiptRecord(run_id=runId, receipt_id=rid, receipt_hash=h, response_json=canonical(result))); db.commit()
        return result
    except ValueError as exc: raise HTTPException(409, detail=str(exc))
