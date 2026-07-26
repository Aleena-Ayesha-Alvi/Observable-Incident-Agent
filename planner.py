"""Safe Gemini-backed planner. A deterministic local plan is used if Gemini is unavailable."""
import json
import os
from utils import redact

def _tools(payload):
    raw = payload.get("tools", payload.get("availableTools", payload.get("incident", {}).get("tools", [])))
    return raw if isinstance(raw, list) else []

def _tool_name(tool): return tool.get("toolName") or tool.get("name") if isinstance(tool, dict) else None

def _fallback(payload):
    incident = payload.get("incident", {})
    causes = incident.get("allowedRootCauses", payload.get("allowedRootCauses", []))
    evidence = incident.get("evidence", payload.get("evidence", []))
    ids = [x.get("id") if isinstance(x, dict) else x for x in evidence]
    if not ids: ids = incident.get("evidenceIds", [])
    # Exact cardinality is impossible with fewer than 2 input ids; duplicate-free deterministic ids
    ids = [str(x) for x in ids][:4]
    tools = _tools(payload)
    # In offline mode, use the first declared diagnostic only. It is an allowed,
    # deterministic and minimal observation; remediation is never guessed.
    diagnostics = []
    if tools:
        name = _tool_name(tools[0])
        if name:
            diagnostics.append({"toolName": name, "arguments": redact(tools[0].get("arguments", {})), "evidence": ids[:2]})
    return {"rootCause": causes[0] if causes else "unknown", "evidence": ids, "diagnostics": diagnostics}

def plan_incident(payload):
    """Return constrained plan without passing sensitive/transcript data to Gemini."""
    safe = redact(payload)
    fallback = _fallback(safe)
    allowed = safe.get("incident", {}).get("allowedRootCauses", safe.get("allowedRootCauses", []))
    tool_names = [_tool_name(t) for t in _tools(safe) if _tool_name(t)]
    max_diagnostics = int(safe.get("policy", {}).get("maximumDiagnostics", len(tool_names) or 0))
    if not os.getenv("GEMINI_API_KEY"):
        return fallback
    try:
        import google.generativeai as genai
        genai.configure(api_key=os.environ["GEMINI_API_KEY"])
        prompt = ("Return only JSON. Choose one rootCause only from " + json.dumps(allowed) +
                  ". Select 2-4 evidence IDs only from supplied IDs. Select only necessary diagnostics "
                  "using toolName only from " + json.dumps(tool_names) + ". Do not include secrets, transcript, or explanations. "
                  "Context: " + json.dumps({"incident": safe.get("incident", {}), "policy": safe.get("policy", {})}))
        text = genai.GenerativeModel(os.getenv("GEMINI_MODEL", "gemini-2.5-flash")).generate_content(prompt).text.strip()
        text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        result = json.loads(text)
        if result.get("rootCause") not in allowed: return fallback
        ev = result.get("evidence", [])
        legal_ev = set(fallback["evidence"])
        if not isinstance(ev, list) or not 2 <= len(ev) <= 4 or any(str(x) not in legal_ev for x in ev): return fallback
        diagnostics = result.get("diagnostics", [])[:max_diagnostics]
        if not all(isinstance(d, dict) and d.get("toolName") in tool_names for d in diagnostics): return fallback
        return {"rootCause": result["rootCause"], "evidence": ev, "diagnostics": diagnostics}
    except Exception:
        return fallback
