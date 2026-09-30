from __future__ import annotations

import functools
import string

from .extract import extract_layered
from .loaders import command_for, load_issues
from .findings import could_outrank, is_fault, layer_of_signal, outrankers, rank
from .select import checks_for_issue, issues_confirming, layer_of, opening_checks
from .observe import observe
from .signals import cost_of, describe as _describe, load_signals, shape_of

NOTHING_PROVABLE = ("Nothing is provable from this evidence, which is not the same claim "
                    "as the device being healthy.")


def _fill(template: str, params: dict, allowed: set[str]) -> tuple[str, list[str]]:
    slots = [f for _, f, _, _ in string.Formatter().parse(template) if f]
    missing = sorted({
        s for s in slots
        if s not in allowed or s not in params or params[s] in (None, "")
    })
    if missing:
        return template, missing
    return template.format(**{s: params[s] for s in slots}), []

MAX_STEPS = 25


def _signal_means(signal: str) -> str:
    for spec in (load_signals() or {}).values():
        for sig in (spec.get("signals") or []):
            if sig.get("name") == signal:
                return sig.get("means") or ""
    return ""


def _start_pool(issue: str | None) -> tuple[frozenset[str], str]:
    if issue:
        checks = checks_for_issue(issue)
        if checks:
            return checks, f"issue named: {issue}"
    pool = frozenset(load_signals())
    return pool, "no issue — asking broadly"


_PARAM_ALIAS = {
    "port":         ("ifname",),
    "interface":    ("ifname", "ospf_if"),
    "peer_address": ("peer_ip",),
}


def _with_aliases(binds: dict) -> dict:
    out = dict(binds)
    for src, targets in _PARAM_ALIAS.items():
        if binds.get(src):
            for t in targets:
                out.setdefault(t, binds[src])
    return out


@functools.lru_cache(maxsize=64)
def _clause_order(issue: str | None) -> dict[str, tuple[int, int]]:
    if not issue:
        return {}
    for doc in load_issues():
        spec = doc.get("issue") or {}
        if spec.get("key") != issue:
            continue
        out: dict[str, tuple[int, int]] = {}
        for st in (doc.get("procedure") or {}).get("steps") or []:
            cap, clause = st.get("capability"), st.get("sop_step")
            if not cap or not clause:
                continue
            parts = [int(n) for n in str(clause).split(".") if n.isdigit()]
            phase = parts[1] if len(parts) > 1 else 9
            step = parts[2] if len(parts) > 2 else 0
            prev = out.get(cap)
            if prev is None or (phase, step) < prev:
                out[cap] = (phase, step)
        return out
    return {}


async def _peer_read_request(local_records: dict, observations: list,
                             vendor: str, trail: list) -> dict | None:
    from .signals import _link_key
    needs_peer = [cap for cap in _compares_both_ends() if local_records.get(cap)]
    if not needs_peer:
        return None
    already = {(o.get("capability") or "") for o in observations
               if (o.get("origin") or "local").lower() == "peer"}
    cap = next((c for c in sorted(needs_peer) if c not in already), None)
    if cap is None:
        return None

    subnets = [k for r in local_records[cap] if (k := _link_key(r))]
    if not subnets:
        return None

    peer_host = None
    for t in trail:
        if t.get("capability") in ("check-lldp-neighbors", "check-ospf-neighbor"):
            for f in ("peer_address", "mgmt_address", "neighbor_ip", "peer"):
                if (v := (t.get("binds") or {}).get(f)):
                    peer_host = v
                    break
        if peer_host:
            break
    if not peer_host:
        lldp = command_for("check-lldp-neighbors", vendor)
        if not lldp or any(t.get("capability") == "check-lldp-neighbors" for t in trail):
            return None
        return {"capability": "check-lldp-neighbors", "command": lldp.command,
                "description": "identify the device on the far end of the link",
                "why": f"{cap} compares both ends and only ours has been read; LLDP names "
                       "the far end without needing the protocol to be up",
                "selected_by": "both-ends comparison needs a peer", "missing_params": []}

    vcmd = command_for(cap, vendor)
    if not vcmd:
        return None
    command = vcmd.command.split("{")[0].strip()
    if not command:
        return None
    return {"capability": cap, "command": command,
            "origin": "peer", "on_device": peer_host,
            "description": f"read {cap} from the far end ({peer_host}) to compare both ends",
            "why": f"{cap} carries a mismatch comparison that one end cannot answer; "
                   f"pairing is by shared subnet ({sorted(set(subnets))[0]})",
            "selected_by": "both-ends comparison", "missing_params": []}


@functools.lru_cache(maxsize=1)
def _compares_both_ends() -> frozenset[str]:
    from .signals import load_signals
    return frozenset(cap for cap, spec in load_signals().items()
                     if any("differs" in s for s in (spec.get("signals") or [])))


async def triage(session, req: dict, *, deterministic: bool = True) -> dict:
    if not deterministic:
        raise ValueError("only the deterministic mode is available")
    vendor = req.get("vendor")
    observations = req.get("observations") or []
    params = dict(req.get("params") or {})

    pool, entry = _start_pool(req.get("issue"))
    seed_issue = req.get("issue")
    trail: list[dict] = []
    ran: set[str] = set()
    seen_output: dict[str, str] = {}
    local_records: dict[str, list[dict]] = {}

    for obs in observations:
        cap = obs.get("capability")
        if not cap:
            continue
        ran.add(cap)
        if obs.get("error"):
            trail.append({"capability": cap, "command": obs.get("command"),
                          "source": "none", "status": "exec_failed", "record_count": 0,
                          "signal": None, "evidence": "", "binds": {},
                          "note": f"command did not run: {obs['error']} — "
                                  "no finding from it",
                          "is_fault": False, "layer": layer_of(cap),
                          "event_source": None})
            continue
        shape = shape_of(cap)
        if shape is None:
            trail.append({"capability": cap, "command": obs.get("command"),
                          "status": "no_signal_contract", "signal": None,
                          "note": "capability has no signals declared — cannot read its output",
                          "is_fault": False, "layer": layer_of(cap),
                          "event_source": None})
            continue
        if obs.get("command"):
            seen_output[obs["command"]] = obs.get("output") or ""
        facts = await extract_layered(vendor or "", obs.get("command") or "",
                                      obs.get("output") or "", shape)
        origin = (obs.get("origin") or "local").strip().lower()
        for r in facts["records"]:
            r["_origin"] = origin
        if origin == "local":
            local_records[cap] = list(facts["records"])
        else:
            merged = list(local_records.get(cap) or []) + list(facts["records"])
            facts = {**facts, "records": merged}
        sig = await observe(cap, facts, context=params, vendor=vendor or "",
                            command=obs.get("command") or "", output=obs.get("output") or "")
        if sig:
            params.update(_with_aliases(sig.get("binds") or {}))
        trail.append({
            "capability": cap,
            "command": obs.get("command"),
            "source": facts["source"],
            "status": facts["status"],
            "record_count": len(facts["records"]),
            "signal": sig["signal"] if sig else None,
            "evidence": (sig or {}).get("evidence") or facts.get("evidence") or "",
            "binds": (sig or {}).get("binds") or {},
            "follow_up": (sig or {}).get("follow_up"),
            "observed_by": (sig or {}).get("observed_by") or ("predicate" if sig else None),
            "predicate_signal": (sig or {}).get("predicate_signal"),
            "is_fault": is_fault(sig["signal"]) if sig else False,
            "layer": layer_of_signal(sig["signal"]) if sig else layer_of(cap),
            "event_source": (facts.get("records") or [{}])[0].get("event_source")
                            if facts.get("records") else None,
            "note": None if sig else "output unreadable — no finding, ask again",
        })

    out: dict = {
        "entry": entry,
        "vendor": vendor,
        "trail": trail,
        "params": params,
        "steps_taken": len(trail),
    }

    def _verdict() -> dict:
        return rank(trail)

    def _cannot_determine(reason: str) -> dict:
        out["next"] = None
        out["escalate"] = reason
        out["cannot_determine"] = True
        return out

    async def _converge(v: dict) -> dict:
        root = v["root_cause"]
        cause = root["signal"]
        family = sorted(issues_confirming(cause))
        issue = family[0] if family else cause
        out["root_cause"] = {
            "cause": cause,
            "means": _signal_means(cause),
            "issue": issue,
            "evidence": [root],
            "symptoms": [{"cause": t["signal"], "evidence": t.get("evidence"),
                          "capability": t.get("capability")} for t in v["symptoms"]],
            "also_found": [{"cause": t["signal"], "evidence": t.get("evidence"),
                            "capability": t.get("capability")} for t in v["also"]],
            "proved_by": {"capability": root.get("capability"),
                          "command": root.get("command"),
                          "line": root.get("evidence"),
                          "read_by": root.get("observed_by"),
                          "layer": root.get("layer")},
            "decided_by": "evidence — signals over extracted facts, no model",
        }
        out["next"] = None
        return out

    v = _verdict()
    out["findings"] = [t["signal"] for t in v["findings"]]
    out["finding_count"] = len(v["findings"])

    _unrun = {c for c in pool if c not in ran and shape_of(c) is not None}
    if v["root_cause"] and not could_outrank(v["root_cause"]["signal"], _unrun):
        return await _converge(v)

    if len(trail) >= MAX_STEPS:
        out["next"] = None
        out["escalate"] = (f"stopped after {len(trail)} checks (budget) — "
                           f"{out['finding_count']} finding(s); hand to an engineer")
        return out

    _COST_ORDER = {"cheap": 0, "moderate": 1, "expensive": 2}

    skipped: list[dict] = []
    deferred: list[dict] = []
    runnable: list[dict] = []
    tried = set(ran)

    _clauses = _clause_order(seed_issue)
    _primary = (v["root_cause"] or {}).get("signal")
    askable = pool if _primary is None else (
        pool & (outrankers(_primary, set(pool)) | set(opening_checks())))

    openers = [c for c in opening_checks()
               if (c in askable or not askable) and c not in _clauses]
    rest = sorted(askable - set(openers),
                  key=lambda c: (_clauses.get(c, (99, 99)),
                                 _COST_ORDER.get(cost_of(c), 9), layer_of(c) or 99, c))
    ordered = [(c, True) for c in openers] + [(c, False) for c in rest]

    for cap, systemic in ordered:
        if cap in tried:
            continue
        tried.add(cap)
        if shape_of(cap) is None:
            continue
        step = {"capability": cap, "cost": cost_of(cap), "layer": layer_of(cap),
                "why": ("systemic — asked before the domain's own questions" if systemic
                        else "in the pool for this alert")}
        if not vendor:
            out["next"] = step
            return out
        vcmd = command_for(cap, vendor)
        if vcmd is None:
            skipped.append({"capability": cap, "why": f"no {vendor} command in the catalog"})
            continue
        cmd, missing = _fill(vcmd.command, params, set(vcmd.params or []))

        if not missing and cmd in seen_output:
            facts = await extract_layered(vendor or "", cmd, seen_output[cmd], shape_of(cap))
            sig = await observe(cap, facts, context=params, vendor=vendor or "",
                                command=cmd, output=seen_output[cmd])
            if sig:
                params.update(_with_aliases(sig.get("binds") or {}))
            trail.append({
                "capability": cap, "command": cmd,
                "source": facts["source"], "status": facts["status"],
                "record_count": len(facts["records"]),
                "signal": sig["signal"] if sig else None,
                "evidence": (sig or {}).get("evidence") or facts.get("evidence") or "",
                "binds": (sig or {}).get("binds") or {},
                "follow_up": (sig or {}).get("follow_up"),
                "observed_by": (sig or {}).get("observed_by") or ("predicate" if sig else None),
                "predicate_signal": (sig or {}).get("predicate_signal"),
                "is_fault": is_fault(sig["signal"]) if sig else False,
                "layer": layer_of_signal(sig["signal"]) if sig else layer_of(cap),
                "event_source": (facts.get("records") or [{}])[0].get("event_source")
                                if facts.get("records") else None,
                "reused": cmd,
                "note": None if sig else "output unreadable — no finding",
            })
            v = _verdict()
            out["trail"], out["params"] = trail, params
            out["steps_taken"] = len(trail)
            out["findings"] = [t["signal"] for t in v["findings"]]
            out["finding_count"] = len(v["findings"])
            continue

        if missing:
            deferred.append({"capability": cap, "command_template": vcmd.command,
                             "needs": missing})
            skipped.append({"capability": cap,
                            "why": f"needs params not bound yet: {missing}"})
            continue
        step["command"] = cmd
        step["missing_params"] = []
        step["description"] = getattr(vcmd, "description", None) or _describe(cap)
        runnable.append(step)

    if runnable:
        step = runnable[0]
        step["selected_by"] = ("no choice — one option" if len(runnable) == 1
                               else "first in the procedure order")
        step["menu"] = [s["capability"] for s in runnable]
        if skipped:
            step["skipped"] = skipped
        if deferred:
            out["deferred"] = deferred
        out["next"] = step
        return out

    if (peer_step := await _peer_read_request(local_records, observations,
                                              vendor or "", trail)):
        out["next"] = peer_step
        if deferred:
            out["deferred"] = deferred
        return out

    if deferred:
        out["deferred"] = deferred
    v = _verdict()
    if v["root_cause"]:
        return await _converge(v)
    return _cannot_determine(
        f"{len(v['health'])} health reading(s) and no fault signal matched. "
        + NOTHING_PROVABLE
        + (f" Passed over {len(skipped)}: "
           + "; ".join(f"{x['capability']} ({x['why']})" for x in skipped[:4])
           if skipped else ""))
