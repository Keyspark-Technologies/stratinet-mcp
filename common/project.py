import copy
import json
from typing import Any

PROTECTED = frozenset({"verdict", "evidence", "need"})


class ResponseTooLarge(RuntimeError):
    pass


def project(payload: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {name: payload[name] for name in fields if name in payload}


def response_size(payload: dict[str, Any]) -> int:
    return len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))


def fit(payload: dict[str, Any], max_bytes: int, shed: tuple[str, ...]) -> dict[str, Any]:
    protected = PROTECTED.intersection(shed)
    if protected:
        raise ValueError(f"never shed {sorted(protected)}")
    out = copy.deepcopy(payload)
    limits = out.get("limits")
    out["limits"] = {**(limits if isinstance(limits, dict) else {}), "response_truncated": False}
    for name in shed:
        items = out.get(name)
        if not isinstance(items, list):
            continue
        while items and response_size(out) > max_bytes:
            items.pop()
            out["limits"]["response_truncated"] = True
    if response_size(out) > max_bytes:
        raise ResponseTooLarge("response exceeds its size budget after shedding")
    return out
