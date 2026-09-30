from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

import yaml

from server.data import data_dir

def _sop_dir() -> Path:
    return data_dir() / "sop"

_BLIND = {"unparseable", "error"}


def _confirms_an_issue(name: str | None) -> bool:
    if not name:
        return False
    from .select import issues_confirming
    return bool(issues_confirming(name))


@functools.lru_cache(maxsize=1)
def load_signals() -> dict[str, dict]:
    doc = yaml.safe_load((_sop_dir() / "signals.yaml").read_text()) or {}
    specs = {k: v for k, v in doc.items() if isinstance(v, dict)}
    for cap, spec in specs.items():
        inc = spec.get("includes") or []
        if not inc:
            continue
        borrowed: list[dict] = []
        for other in inc:
            src = specs.get(other) or {}
            if src.get("shape") != spec.get("shape"):
                raise ValueError(
                    f"{cap} includes {other}, but their shapes differ "
                    f"({spec.get('shape')!r} vs {src.get('shape')!r})")
            borrowed += [s for s in (src.get("signals") or [])
                         if _confirms_an_issue(s.get("name"))]
        own = spec.get("signals") or []
        have = {s.get("name") for s in own}
        spec["signals"] = [s for s in borrowed if s.get("name") not in have] + own
    return specs


def _link_key(rec: dict) -> str | None:
    addr, plen = rec.get("address"), rec.get("prefix_len")
    if not addr or plen in (None, ""):
        return None
    try:
        import ipaddress
        return str(ipaddress.ip_network(f"{addr}/{plen}", strict=False))
    except ValueError:
        return None


def _differing_pair(sig: dict, records: list[dict]) -> tuple[dict, dict] | None:
    spec = sig["differs"] or {}
    field = spec.get("field")
    a, b = (spec.get("between") or ["local", "peer"])[:2]
    sides: dict[str, list[dict]] = {a: [], b: []}
    for r in records:
        o = str(r.get("_origin") or "local")
        if o in sides and r.get(field) not in (None, ""):
            sides[o].append(r)
    if not sides[a] or not sides[b]:
        return None

    def _differs(x: dict, y: dict) -> bool:
        return str(x[field]).strip().lower() != str(y[field]).strip().lower()

    keyed_a = {k: r for r in sides[a] if (k := _link_key(r))}
    keyed_b = {k: r for r in sides[b] if (k := _link_key(r))}
    shared = set(keyed_a) & set(keyed_b)
    if shared:
        for k in sorted(shared):
            if _differs(keyed_a[k], keyed_b[k]):
                return (keyed_a[k], keyed_b[k])
        return None
    if len(sides[a]) == 1 and len(sides[b]) == 1:
        if _differs(sides[a][0], sides[b][0]):
            return (sides[a][0], sides[b][0])
    return None


def _match(rec: dict, field: str, want: Any) -> bool:
    have = rec.get(field)
    if have is None:
        return False
    return str(have).strip().lower() == str(want).strip().lower()


def _fits(sig: dict, facts: dict) -> bool:
    status = facts.get("status")
    records = facts.get("records") or []

    if "status" in sig:
        return status == sig["status"]

    if status in _BLIND:
        return False

    if "any" in sig:
        f, v = next(iter(sig["any"].items()))
        return any(_match(r, f, v) for r in records)

    if "none" in sig:
        f, v = next(iter(sig["none"].items()))
        return bool(records) and not any(_match(r, f, v) for r in records)

    if "all" in sig:
        f, v = next(iter(sig["all"].items()))
        return bool(records) and all(_match(r, f, v) for r in records)

    if "count" in sig:
        op, n = next(iter(sig["count"].items()))
        c = len(records)
        return {"gt": c > n, "lt": c < n, "eq": c == n}.get(op, False)

    if "contains" in sig:
        f, want = next(iter(sig["contains"].items()))
        needle = str(want).strip().lower()
        return any(needle in str(r.get(f) or "").lower() for r in records)

    if "differs" in sig:
        return _differing_pair(sig, records) is not None

    if "field" in sig:
        def _holds(r: dict) -> bool:
            for name, cmp in sig["field"].items():
                op, n = next(iter(cmp.items()))
                raw = r.get(name)
                if raw is None:
                    return False
                try:
                    v = float(str(raw).strip())
                except ValueError:
                    return False
                if not {"gt": v > n, "lt": v < n, "eq": v == n, "gte": v >= n,
                        "lte": v <= n}.get(op, False):
                    return False
            return True

        return any(_holds(r) for r in records)

    return False


def _binding_record(sig: dict, facts: dict, context: dict | None = None) -> dict | None:
    records = facts.get("records") or []
    if not records:
        return None

    scope = (context or {}).get("port") or (context or {}).get("interface")

    def _prefer(cands: list[dict]) -> dict | None:
        if context:
            for r in cands:
                for k, v in context.items():
                    if k in r and str(r[k]).strip().lower() == str(v).strip().lower():
                        return r
                if scope:
                    for field in ("port", "interface", "local_interface"):
                        if str(r.get(field, "")).strip().lower() == str(scope).strip().lower():
                            return r
        if scope:
            return None
        return cands[0]

    for form in ("any", "all"):
        if form in sig:
            f, v = next(iter(sig[form].items()))
            matched = [r for r in records if _match(r, f, v)]
            return _prefer(matched or records)

    if "contains" in sig:
        f, want = next(iter(sig["contains"].items()))
        needle = str(want).strip().lower()
        matched = [r for r in records if needle in str(r.get(f) or "").lower()]
        return _prefer(matched or records)

    if "differs" in sig:
        fld = (sig["differs"] or {}).get("field")
        pair = _differing_pair(sig, records)
        if pair:
            local, peer = pair
            r = dict(peer)
            line = r.get(f"_line_{fld}")
            if line:
                r["_line"] = line
            r["_compared_with"] = local.get(f"_line_{fld}") or local.get("_line")
            r["_local_value"], r["_peer_value"] = local.get(fld), peer.get(fld)
            return r
        with_field = [r for r in records if r.get(fld) not in (None, "")]
        if with_field:
            r = dict(with_field[0])
            line = r.get(f"_line_{fld}")
            if line:
                r["_line"] = line
            return r
        return _prefer(records)

    if "field" in sig:
        matched = [r for r in records if _fits({"field": sig["field"]},
                                               {"records": [r], "status": "ok"})]
        return _prefer(matched or records)

    return _prefer(records)


def evaluate(capability: str, facts: dict, context: dict | None = None) -> dict | None:
    spec = load_signals().get(capability)
    if not spec:
        return None
    for sig in spec.get("signals") or []:
        if not _fits(sig, facts):
            continue
        rec = _binding_record(sig, facts, context)
        binds = {}
        for field in sig.get("binds") or []:
            if rec and rec.get(field) not in (None, ""):
                binds[field] = rec[field]
        evidence = ""
        if rec and "field" in sig:
            evidence = next((rec[f"_line_{name}"] for name in sig["field"]
                             if rec.get(f"_line_{name}")), "")
        evidence = evidence or (rec or {}).get("_line") or facts.get("evidence") or ""
        return {"signal": sig["name"],
                "evidence": evidence,
                "binds": binds,
                "source": facts.get("source"),
                "follow_up": sig.get("follow_up"),
                "record_count": len(facts.get("records") or [])}
    return None


def shape_of(capability: str) -> str | None:
    spec = load_signals().get(capability)
    return spec.get("shape") if spec else None


def describe(capability: str) -> str:
    spec = load_signals().get(capability) or {}
    return spec.get("description") or capability.replace("check-", "").replace("-", " ")


def cost_of(capability: str) -> str:
    spec = load_signals().get(capability) or {}
    return spec.get("cost", "moderate")


def is_systemic(capability: str) -> bool:
    return bool((load_signals().get(capability) or {}).get("systemic"))
