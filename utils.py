"""
utils.py
"""

import hashlib
import json
import secrets
from copy import deepcopy


REDACT_KEYS = {
    "authorization",
    "access_token",
    "accessToken",
    "apiKey",
    "apikey",
    "password",
    "secret",
    "token",
    "privateNote",
    "sensitive",
}


def canonical(obj):
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def digest(obj):
    return hashlib.sha256(
        canonical(obj).encode("utf-8")
    ).hexdigest()


def stable_id(prefix, *parts):
    h = hashlib.sha256()

    for part in parts:
        h.update(str(part).encode("utf-8"))
        h.update(b"|")

    return prefix + h.hexdigest()[:24]


def trace_id(seed=None):
    if seed:
        return hashlib.sha256(
            str(seed).encode()
        ).hexdigest()[:32]

    while True:
        tid = secrets.token_hex(16)
        if tid != "0" * 32:
            return tid


def span_id(seed=None):
    if seed:
        return hashlib.sha256(
            str(seed).encode()
        ).hexdigest()[:16]

    while True:
        sid = secrets.token_hex(8)
        if sid != "0" * 16:
            return sid


def parse_traceparent(header):
    if not header:
        return None

    try:
        version, trace, parent, flags = header.split("-")
        if version != "00":
            return None

        if (
            len(trace) != 32
            or len(parent) != 16
        ):
            return None

        return (
            trace.lower(),
            parent.lower(),
            flags.lower(),
        )

    except Exception:
        return None


def _redact(value):
    if isinstance(value, dict):

        result = {}

        for key, val in value.items():

            if str(key).lower() in {
                k.lower() for k in REDACT_KEYS
            }:
                result[key] = "[REDACTED]"
            else:
                result[key] = _redact(val)

        return result

    if isinstance(value, list):
        return [_redact(v) for v in value]

    return value


def redact(obj):
    return _redact(deepcopy(obj))