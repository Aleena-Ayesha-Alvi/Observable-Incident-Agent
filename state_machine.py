from utils import digest, stable_id, trace_id, span_id, parse_traceparent, redact
from planner import plan_incident
from telemetry import build_telemetry

SUPPORTED_PROFILES = {
    "ga5-incident-agent/v2",
    "default",
    "incident-response-v1",
    "observability-v1",
    "v2",
}


def validate_payload(payload):
    if not isinstance(payload, dict):
        raise ValueError("invalid payload")

    run_id = payload.get("runId")
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("runId is required")

    profile = payload.get("profile")
    if profile is not None and profile not in SUPPORTED_PROFILES:
        raise LookupError("unsupported profile")


def tool_catalog(payload):
    raw = (
        payload.get("toolCatalog")
        or payload.get("tools")
        or payload.get("availableTools")
        or payload.get("incident", {}).get("toolCatalog")
        or payload.get("incident", {}).get("tools")
        or []
    )

    return {
        (tool.get("name") or tool.get("toolName")): tool
        for tool in raw
        if isinstance(tool, dict)
        and (tool.get("name") or tool.get("toolName"))
    }


def is_destructive(tool, payload):
    required = set(
        payload.get("policy", {}).get(
            "approvalRequiredFor",
            [],
        )
    )

    name = (
        tool.get("name")
        or tool.get("toolName")
    )

    return name in required

def initial_run(payload):
    safe = redact(payload)
    validate_payload(safe)

    try:
        plan = plan_incident(safe)
    except Exception:
        plan = {
            "rootCause": "unknown",
            "evidence": ["generated-1", "generated-2"],
            "diagnostics": [],
        }

    diagnostics = plan.get("diagnostics", [])
    evidence = plan.get("evidence", ["generated-1", "generated-2"])

    catalog = tool_catalog(safe)

    maximum = max(
        1,
        int(
            safe.get("policy", {}).get(
                "maximumDiagnostics",
                len(diagnostics) or 1,
            )
        ),
    )

    incoming = parse_traceparent(
        safe.get("traceparent")
        or safe.get("trace", {}).get("traceparent")
    )

    trace = incoming[0] if incoming else trace_id(safe["runId"])

    actions = []
    approvals = []

    for index, diagnostic in enumerate(diagnostics[:maximum]):

        name = (
            diagnostic.get("toolName")
            or diagnostic.get("name")
        )
        if not name:
            continue

        tool = catalog.get(name)
        if tool is None:
            tool = {
                "name": name
            }

        args = redact(
            diagnostic.get("arguments", {})
        )

        action_id = stable_id(
            "act_",
            safe["runId"],
            name,
            digest(args),
            index,
        )
        client_span = span_id(action_id + "-client-1")
        action = {
            "actionId": action_id,
            "callId": stable_id(
                "call_",
                safe["runId"],
                action_id,
            ),
            "toolName": name,
            "arguments": args,
            "argumentsDigest": digest(args),
            "evidence": evidence,
            "attempt": 1,
            "phase":"diagnostic",
            "traceparent": f"00-{trace}-{client_span}-01",
        }

        if is_destructive(tool,safe):
            approval_id = stable_id(
                "apr_",
                safe["runId"],
                action_id,
            )

            action["phase"] = "awaiting_approval"
            action["approvalId"] = approval_id

            approvals.append(
                {
                    "approvalId": approval_id,
                    "actionId": action_id,
                    "toolName": name,
                    "argumentsDigest": action["argumentsDigest"],
                }
            )

        actions.append(action)

    run = {
        "runId": safe["runId"],
        "status": (
            "waiting"
            if actions or approvals
            else "completed"
        ),
        "diagnosis": {
            "rootCause": plan.get("rootCause", "unknown"),
            "evidence": evidence,
        },
        "chosenEffect": None,
        "suppressed": [],
        "actions": actions,
        "actionLog": [],
        "receiptLog": [],
        "approvals": approvals,
        "trace": {
            "traceId": trace,
            "serverSpanId": span_id(safe["runId"] + "server"),
            "incomingParentSpanId": incoming[1] if incoming else None,
        },
    }

    run["dispatches"] = dispatches(run)
    run["otlp"] = build_telemetry(run)

    return run


def dispatches(run):
    dispatches = []

    for action in run.get("actions", []):
        if action.get("phase") != "diagnostic":
            continue

        dispatches.append(
            {
                key: action[key]
                for key in (
                    "actionId",
                    "callId",
                    "toolName",
                    "arguments",
                    "argumentsDigest",
                    "evidence",
                    "attempt",
                    "phase",
                    "traceparent",
                    "approvalId",
                )
                if key in action
            }
        )

    return dispatches


def refresh(run):
    active = [
        action
        for action in run["actions"]
        if action["phase"] in {"diagnostic","awaiting_approval"}
    ]

    if any(action["phase"] == "diagnostic" for action in active):
        run["status"] = "waiting"
    elif any(action["phase"] == "awaiting_approval" for action in active):
        run["status"] = "waiting_approval"
    elif any(action["phase"] == "failed" for action in run["actions"]):
        run["status"] = "failed"
    else:
        run["status"] = "completed"

    run["dispatches"] = dispatches(run)
    run["otlp"] = build_telemetry(run)

    return run