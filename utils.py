"""Small deterministic helpers used by API, state and telemetry code."""
import copy
import hashlib
import json
import re
import uuid

SENSITIVE_KEYS = {"sensitive", "authorization", "token", "password", "secret", "api_key", "apikey", "transcript", "prompt", "tool_results", "tool_result"}

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def stable_id(prefix, *parts, length=32):
    return prefix + hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:length]

def trace_id(seed):
    return hashlib.sha256(("trace|" + seed).encode()).hexdigest()[:32]

def span_id(seed):
    return hashlib.sha256(("span|" + seed).encode()).hexdigest()[:16]

def parse_traceparent(value):
    if not isinstance(value, str): return None
    match = re.fullmatch(r"00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})", value.lower())
    return match.groups() if match else None

def redact(value):
    """Remove fields which are never allowed in storage, response, or OTLP."""
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items() if k.lower() not in SENSITIVE_KEYS}
    if isinstance(value, list): return [redact(v) for v in value]
    return copy.deepcopy(value)

def jsonable(value):
    return json.loads(canonical(value))
