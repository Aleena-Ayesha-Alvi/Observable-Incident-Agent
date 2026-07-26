"""Dependency-free OTLP/JSON exporter. It deliberately contains only safe attributes."""

from datetime import datetime, timezone
from utils import span_id


def now_ns():
    return str(int(datetime.now(timezone.utc).timestamp() * 1_000_000_000))


SPAN_KINDS = {
    "INTERNAL": 1,
    "SERVER": 2,
    "CLIENT": 3,
}


def _attribute(key, value):
    if isinstance(value, bool):
        encoded = {"boolValue": value}
    elif isinstance(value, int):
        encoded = {"intValue": str(value)}
    else:
        encoded = {"stringValue": str(value)}

    return {
        "key": key,
        "value": encoded,
    }


def span(
    name,
    trace,
    parent,
    seed,
    kind="INTERNAL",
    status="UNSET",
    attributes=None,
):
    data = {
        "traceId": trace,
        "spanId": span_id(seed),
        "name": name,
        "kind": SPAN_KINDS[kind],
        "startTimeUnixNano": now_ns(),
        "endTimeUnixNano": now_ns(),
        "status": {"code": status},
        "attributes": [
            _attribute(k, v)
            for k, v in (attributes or {}).items()
        ],
    }

    if parent:
        data["parentSpanId"] = parent

    return data


def build_telemetry(run):
    trace = run["trace"]["traceId"]
    server = run["trace"]["serverSpanId"]

    spans = [
        span(
            "SERVER POST /v2/incidents",
            trace,
            run["trace"].get("incomingParentSpanId"),
            server,
            kind="SERVER",
            attributes={
                "ga5.run_id": run["runId"],
            },
        )
    ]

    agent = span(
        "incident.agent",
        trace,
        server,
        run["runId"] + "agent",
    )

    planner = span(
        "incident.planner",
        trace,
        agent["spanId"],
        run["runId"] + "planner",
    )

    join = span(
        "incident.join",
        trace,
        agent["spanId"],
        run["runId"] + "join",
    )

    spans.extend([agent, planner])

    for action in run.get("actions", []):

        execute = span(
            "execute_tool",
            trace,
            agent["spanId"],
            action["actionId"],
            attributes={
                "ga5.action.id": action["actionId"],
                "ga5.tool.name": action["toolName"],
                "ga5.attempt": action["attempt"],
            },
        )

        client = span(
            "tool.client",
            trace,
            execute["spanId"],
            action["callId"],
            kind="CLIENT",
            attributes={
                "ga5.tool.name": action["toolName"],
                "ga5.attempt": action["attempt"],
            },
        )

        spans.extend([execute, client])

        if action.get("approvalId"):
            spans.append(
                span(
                    "approval_gate",
                    trace,
                    agent["spanId"],
                    action["approvalId"],
                    attributes={
                        "approval.id": action["approvalId"],
                    },
                )
            )

    spans.append(join)

    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {
                            "key": "service.name",
                            "value": {
                                "stringValue": "observable-incident-agent"
                            },
                        }
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {
                            "name": "observable-incident-agent",
                        },
                        "spans": spans,
                    }
                ],
            }
        ]
    }