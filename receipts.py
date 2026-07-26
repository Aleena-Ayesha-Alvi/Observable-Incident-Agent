from state_machine import refresh
from utils import redact, stable_id


def apply_receipt(run, receipt):
    safe = redact(receipt)
    rid = safe.get("receiptId")
    if not isinstance(rid, str) or not rid:
        raise ValueError("receiptId is required")
    action_id = safe.get("actionId")
    action = next((a for a in run["actions"] if a["actionId"] == action_id), None)
    if not action:
        raise ValueError("unknown actionId")
    # Approval receipts are tied to a pending approval and cause delayed dispatch.
    if safe.get("approvalId") or safe.get("type") == "approval":
        approval_id = safe.get("approvalId")
        approval = next((a for a in run["approvals"] if a["approvalId"] == approval_id and a["actionId"] == action_id), None)
        if not approval or action["phase"] != "awaiting_approval":
            raise ValueError("approval is not pending")
        approved = safe.get("approved", safe.get("status") in {"approved", "success"})
        approval["status"] = "approved" if approved else "rejected"
        action["phase"] = "pending" if approved else "failed"
        event = {"receiptId": rid, "actionId": action_id, "type": "approval", "status": approval["status"]}
    else:
        if action["phase"] != "pending":
            raise ValueError("action is not pending")
        status = str(safe.get("status", "success")).lower()
        if status in {"503", "http_503", "service_unavailable"} and action["attempt"] == 1:
            action["attempt"] = 2
            action["callId"] = stable_id("call_", run["runId"], action["actionId"], 2)
            event = {"receiptId": rid, "actionId": action_id, "status": "retrying", "attempt": 2}
        elif status in {"timeout", "timed_out", "failed", "error", "503", "http_503", "service_unavailable"}:
            action["phase"] = "failed"
            event = {"receiptId": rid, "actionId": action_id, "status": "failed", "attempt": action["attempt"]}
        else:
            action["phase"] = "completed"
            event = {"receiptId": rid, "actionId": action_id, "status": "completed", "attempt": action["attempt"]}
    run["receiptLog"].append(event)
    run["actionLog"].append({"actionId": action_id, "phase": action["phase"], "attempt": action["attempt"]})
    refresh(run)
    return {"runId": run["runId"], "receiptId": rid, "status": event["status"], "incidentStatus": run["status"], "dispatches": run["dispatches"]}
