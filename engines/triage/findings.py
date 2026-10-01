from __future__ import annotations

import functools

from .select import issues_confirming
from .signals import load_signals

_DEVICE_PLANE = 99


def is_fault(signal: str | None) -> bool:
    return bool(signal) and bool(issues_confirming(signal))


@functools.lru_cache(maxsize=1)
def _home() -> dict[str, tuple[int, int]]:
    out: dict[str, tuple[int, int]] = {}
    for cap, spec in load_signals().items():
        borrowed = set()
        for other in spec.get("includes") or []:
            borrowed |= {s.get("name")
                         for s in (load_signals().get(other) or {}).get("signals") or []}
        raw = spec.get("layer")
        layer = int(raw) if isinstance(raw, (int, str)) and str(raw).isdigit() else 0
        for i, sig in enumerate(spec.get("signals") or []):
            name = sig.get("name")
            if name and name not in borrowed and name not in out:
                out[name] = (layer or _DEVICE_PLANE, i)
    return out


def layer_of_signal(signal: str) -> int:
    return _home().get(signal, (_DEVICE_PLANE, 0))[0]


@functools.lru_cache(maxsize=1)
def _explains() -> dict[str, frozenset[str]]:
    out: dict[str, set[str]] = {}
    for spec in load_signals().values():
        for sig in spec.get("signals") or []:
            name, ex = sig.get("name"), sig.get("explains") or []
            if name and ex:
                out.setdefault(name, set()).update(ex)
    return {k: frozenset(v) for k, v in out.items()}


def rank(trail: list[dict]) -> dict:
    seen: dict[str, dict] = {}
    for t in trail:
        sig = t.get("signal")
        if is_fault(sig) and sig not in seen:
            seen[sig] = t
    findings = list(seen.values())
    health = [t for t in trail if t.get("signal") and not is_fault(t.get("signal"))]
    if not findings:
        return {"root_cause": None, "symptoms": [], "also": [], "findings": [],
                "health": health}

    names = {t["signal"] for t in findings}
    explained: set[str] = set()
    for n in names:
        explained |= (_explains().get(n, frozenset()) & names)

    def key(t: dict) -> tuple:
        sig = t["signal"]
        layer, spec_index = _home().get(sig, (_DEVICE_PLANE, 0))
        device_named = 0 if t.get("event_source") == "device" else 1
        return (layer, device_named, spec_index, sig)

    primary_pool = [t for t in findings if t["signal"] not in explained] or findings
    ordered = sorted(primary_pool, key=key)
    root = ordered[0]

    symptoms = [t for t in findings if t is not root and t["signal"] in explained]
    also = [t for t in findings if t is not root and t["signal"] not in explained]
    return {"root_cause": root,
            "symptoms": sorted(symptoms, key=key),
            "also": sorted(also, key=key),
            "findings": sorted(findings, key=key),
            "health": health}


def fault_signals(capability: str) -> frozenset[str]:
    spec = load_signals().get(capability) or {}
    return frozenset(s["name"] for s in (spec.get("signals") or [])
                     if s.get("name") and is_fault(s["name"]))


def outrankers(primary: str | None, unrun: set[str]) -> set[str]:
    if primary is None:
        return set(unrun)
    plevel = layer_of_signal(primary)
    explainers = {s for s, ex in _explains().items() if primary in ex}
    return {cap for cap in unrun
            if any(sig in explainers or layer_of_signal(sig) < plevel
                   for sig in fault_signals(cap))}


def could_outrank(primary: str | None, unrun: set[str]) -> bool:
    if primary is None:
        return True
    plevel = layer_of_signal(primary)
    explainers = {s for s, ex in _explains().items() if primary in ex}
    for cap in unrun:
        for sig in fault_signals(cap):
            if sig in explainers or layer_of_signal(sig) < plevel:
                return True
    return False
