"""Dependency-free OTLP/JSON exporter. It deliberately contains only safe attributes."""
from datetime import datetime, timezone
from utils import span_id

def now_ns(): return str(int(datetime.now(timezone.utc).timestamp() * 1_000_000_000))

def span(name, trace, parent, seed, kind="INTERNAL", status="UNSET", attributes=None):
    data = {"traceId": trace, "spanId": span_id(seed), "name": name, "kind": kind,
            "startTimeUnixNano": now_ns(), "endTimeUnixNano": now_ns(),
            "status": {"code": status}, "attributes": [{"key": k, "value": {"stringValue": str(v)}} for k,v in (attributes or {}).items()]}
    if parent: data["parentSpanId"] = parent
    return data

def build_telemetry(run):
    trace = run["trace"]["traceId"]; server = run["trace"]["serverSpanId"]
    spans = [span("SERVER POST /v2/incidents", trace, run["trace"].get("incomingParentSpanId"), server, "SERVER", attributes={"incident.run_id": run["runId"]})]
    agent = span("incident.agent", trace, span_id(server), run["runId"]+"agent")
    planner = span("incident.planner", trace, span_id(run["runId"]+"agent"), run["runId"]+"planner")
    join = span("incident.join", trace, span_id(run["runId"]+"agent"), run["runId"]+"join")
    spans += [agent, planner]
    for a in run.get("actions", []):
        execute = span("execute_tool", trace, agent["spanId"], a["actionId"], attributes={"action.id": a["actionId"], "attempt": a["attempt"]})
        client = span("tool.client", trace, execute["spanId"], a["callId"], "CLIENT", attributes={"tool.name": a["toolName"], "attempt": a["attempt"]})
        spans += [execute, client]
        if a.get("approvalId"): spans.append(span("approval_gate", trace, agent["spanId"], a["approvalId"], attributes={"approval.id": a["approvalId"]}))
    spans.append(join)
    return {"resourceSpans": [{"resource": {"attributes": [{"key":"service.name","value":{"stringValue":"observable-incident-agent"}}]}, "scopeSpans": [{"scope": {"name":"observable-incident-agent"}, "spans": spans}]}]}
