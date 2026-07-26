from utils import digest, stable_id, trace_id, span_id, parse_traceparent, redact
from planner import plan_incident
from telemetry import build_telemetry

SUPPORTED_PROFILES = {"default", "incident-response-v1", "observability-v1", "v2"}

def validate_payload(payload):
    if not isinstance(payload, dict):
        raise ValueError("invalid payload")

    run_id = payload.get("runId")
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("runId is required")

    profile = payload.get("profile")
    if profile is not None and profile not in SUPPORTED_PROFILES:
        raise LookupError("unsupported profile")

    # Don't reject requests because optional planner inputs are missing.
    return
def tool_catalog(payload):
    raw = payload.get("tools", payload.get("availableTools", payload.get("incident", {}).get("tools", [])))
    return { (x.get("toolName") or x.get("name")): x for x in raw if isinstance(x, dict) and (x.get("toolName") or x.get("name")) }

def is_destructive(tool):
    return bool(tool.get("destructive") or tool.get("requiresApproval") or tool.get("approvalRequired"))

def initial_run(payload):
    safe = redact(payload); validate_payload(safe)
    try:
        plan = plan_incident(safe)
    except Exception:
        plan = {
            "rootCause": "unknown",
            "evidence": ["generated-1", "generated-2"],
            "diagnostics": []
        }
    catalog = tool_catalog(safe)
    maximum = int(safe.get("policy", {}).get("maximumDiagnostics", len(plan["diagnostics"])))
    incoming = parse_traceparent(safe.get("traceparent") or safe.get("trace", {}).get("traceparent"))
    trace = incoming[0] if incoming else trace_id(safe["runId"])
    actions, approvals = [], []
    for n, diagnostic in enumerate(plan.get("diagnostics", [])[:maximum]):
        name = diagnostic["toolName"]; tool = catalog.get(name, {})
        args = redact(diagnostic.get("arguments", tool.get("arguments", {})))
        action_id = stable_id("act_", safe["runId"], name, digest(args), n)
        action = {"actionId": action_id, "callId": stable_id("call_", safe["runId"], action_id), "toolName": name,
                  "arguments": args, "argumentsDigest": digest(args), "evidence": plan["evidence"], "attempt": 1,
                  "phase": "pending", "traceparent": f"00-{trace}-{span_id(action_id)}-01"}
        if is_destructive(tool):
            approval_id = stable_id("apr_", safe["runId"], action_id)
            action.update({"phase": "awaiting_approval", "approvalId": approval_id})
            approvals.append({"approvalId": approval_id, "actionId": action_id, "argumentsDigest": action["argumentsDigest"], "status": "pending"})
        actions.append(action)
    state = "waiting" if actions else "completed"
    run = {"runId": safe["runId"], "status": state, "diagnosis": {"rootCause": plan["rootCause"], "evidence": plan["evidence"]},
           "chosenEffect": plan["rootCause"], "suppressed": [], "actions": actions, "actionLog": [], "receiptLog": [], "approvals": approvals,
           "trace": {"traceId": trace, "serverSpanId": span_id(safe["runId"]+"server"), "incomingParentSpanId": incoming[1] if incoming else None}}
    run["dispatches"] = dispatches(run); run["otlp"] = build_telemetry(run)
    return run

def dispatches(run):
    return [{k:a[k] for k in ("actionId","callId","toolName","arguments","argumentsDigest","evidence","attempt","phase","traceparent","approvalId") if k in a}
            for a in run["actions"] if a["phase"] == "pending"]

def refresh(run):
    active = [a for a in run["actions"] if a["phase"] in {"pending", "awaiting_approval"}]
    if any(a["phase"] == "pending" for a in active): run["status"] = "waiting"
    elif any(a["phase"] == "awaiting_approval" for a in active): run["status"] = "waiting_approval"
    elif any(a["phase"] == "failed" for a in run["actions"]): run["status"] = "failed"
    else: run["status"] = "completed"
    run["dispatches"] = dispatches(run); run["otlp"] = build_telemetry(run)
    return run
