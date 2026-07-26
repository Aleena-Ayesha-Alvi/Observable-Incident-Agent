# Observable Incident Agent

FastAPI service for durable incident orchestration. It persists runs and receipt replays in SQLite, keeps sensitive fields out of persistence/responses/telemetry, and emits valid OTLP JSON under `otlp` on each incident state.

## Run locally

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app:app --host 0.0.0.0 --port 8000
```

`GEMINI_API_KEY` is optional. When set, Gemini receives only a redacted planning context; when absent or unavailable, a deterministic constrained planner is used.

## API

`POST /v2/incidents` creates a durable run. A replay with the same sanitized payload returns byte-equivalent JSON; changed content gets `409`. `POST /v2/incidents/{runId}/receipts` processes an action/approval receipt with the same replay behavior. `GET /v2/incidents/{runId}` returns the current state.

A minimal request needs `runId`, `incident.allowedRootCauses`, and evidence IDs. Tool definitions live in `tools`; destructive tools (`destructive`, `requiresApproval`, or `approvalRequired`) wait for an approval receipt.

```json
{
  "runId": "demo-1",
  "profile": "incident-response-v1",
  "incident": {"allowedRootCauses": ["database overload"], "evidence": ["ev-1", "ev-2"]},
  "tools": [{"name": "check_database"}]
}
```

## Deploy to Render

Push this workspace to a Git repository, create a Render Blueprint from it, and set `GEMINI_API_KEY` only if Gemini planning is wanted. For production durable storage, set `DATABASE_URL` to a managed persistent database (Render disks are required for SQLite persistence across deploys).
