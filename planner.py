"""
planner.py

Gemini-backed incident planner with deterministic fallback.
"""

import json
import os

from utils import redact


def _tool_catalog(payload):
    tools = (
        payload.get("toolCatalog")
        or payload.get("tools")
        or []
    )

    result = []

    for tool in tools:
        if isinstance(tool, dict):
            name = (
                tool.get("name")
                or tool.get("toolName")
            )
            if name:
                result.append(tool)

    return result


def _fallback(payload):
    incident = payload["incident"]

    causes = incident.get("allowedRootCauses", [])

    root = causes[0] if causes else "unknown"

    transcript = incident.get("transcript", "")

    evidence = []

    for line in transcript.splitlines():
        line = line.strip()
        if line.startswith("[") and "]" in line:
            evidence.append(line.split("]")[0][1:])

    evidence = evidence[:4]

    while len(evidence) < 2:
        evidence.append(f"generated-{len(evidence)+1}")

    diagnostics = []

    tools = _tool_catalog(payload)

    if tools:
        diagnostics.append(
            {
                "toolName": tools[0]["name"],
                "arguments": {},
                "evidence": evidence[:2],
            }
        )

    return {
        "rootCause": root,
        "evidence": evidence,
        "diagnostics": diagnostics,
    }


def plan_incident(payload):

    safe = redact(payload)

    fallback = _fallback(safe)

    if "GEMINI_API_KEY" not in os.environ:
        return fallback

    try:

        import google.generativeai as genai

        genai.configure(
            api_key=os.environ["GEMINI_API_KEY"]
        )

        model = genai.GenerativeModel(
            os.getenv(
                "GEMINI_MODEL",
                "gemini-2.5-flash",
            )
        )

        allowed = safe["incident"].get(
            "allowedRootCauses",
            [],
        )

        tools = [
            t["name"]
            for t in _tool_catalog(safe)
        ]

        prompt = f"""
You are an incident response planner.

Return ONLY JSON.

Schema:

{{
  "rootCause":"one of {allowed}",
  "evidence":["id1","id2"],
  "diagnostics":[
      {{
        "toolName":"one of {tools}",
        "arguments":{{}},
        "evidence":["id1"]
      }}
  ]
}}

Rules:

- Pick exactly one allowed root cause.
- Choose 2-4 evidence IDs.
- Use at most 3 diagnostic tools.
- Never include explanations.
- Never include markdown.
- Never include transcript.
- Never reveal secrets.

Incident:

{json.dumps(safe["incident"])}
"""

        response = model.generate_content(prompt)

        text = (
            response.text
            .replace("```json", "")
            .replace("```", "")
            .strip()
        )

        result = json.loads(text)
        diagnostics = result.get("diagnostics", [])

        valid_tools = set(tools)

        diagnostics = [
            d
            for d in diagnostics
            if d.get("toolName") in valid_tools
        ]

        result["diagnostics"] = diagnostics[:3]

        if (
            result.get("rootCause")
            not in allowed
        ):
            return fallback

        return result

    except Exception:
        return fallback