"""Rank the faults a run found, instead of eliminating candidates until one survives.

WHY ELIMINATION WENT.

The engine used to seed a candidate set from the alert and narrow it with every answer:
a signal's `confirms` kept issues, its `excludes` dropped them, and a verdict required
exactly one survivor WITH a confirming signal. Measured over one day of real faults, four
of seven bugs came from that machinery and none from the evidence:

    ospf-healthy was `any: {state: full}`   one healthy neighbour outvoted a broken one
    ospf-healthy EXCLUDED ospf-neighbor-down  it ruled out what the log proved 2 rounds later
    ping-peer check-membership              dropped an issue for not listing a check
    a verified issue with 0 confirms        a candidate that could never be proven

The evidence was right every time. On a lab router the device logged
`Duplicate Router ID 1.1.1.1 detected in area 0.0.0.0` fifty-eight times in an hour, the
signal fired and quoted it, and the run reported NO FAULT FOUND — because the issue that
signal confirmed had already been voted out by a HEALTHY signal. An issue had to survive
every other check before its own evidence was allowed to count.

And 467 of 539 issue files (86%) carried no confirming signal at all, so they could never
be a verdict — they existed only to be eliminated.

WHAT REPLACES IT.

Every fault signal that fires is a FINDING, with the line that proves it. Findings are
ranked, not eliminated. The asymmetry is the whole point: a wrong RANK still shows the
other findings, while a wrong elimination hides them completely.

    1. EXPLAINED findings drop to symptoms. A cause keeps its symptoms — as symptoms,
       listed below it, never deleted. An admin-shut interface explains a lost adjacency;
       the adjacency loss is real and is not the thing to go and fix.
    2. Among the rest, LOWER OSI LAYER FIRST. A down interface explains a failed
       adjacency and never the reverse. Layer 0 is the device/platform plane — logs,
       version, clock, memory — which is NOT "below layer 1", so it sorts last.
    3. At the same layer, A FAULT THE DEVICE NAMED ITSELF beats one we inferred. A log
       line where the device reports its own error is the device's own testimony;
       everything else is our reading of a table.
    4. Still tied: the MORE SPECIFIC signal, which is declaration order — signals are
       authored specific-first because the first that fits wins.

A finding's layer comes from the capability that DECLARES its signal, not the one that
happened to read it: `ospf-log-duplicate-router-id` is a layer-3 OSPF fault even when the
layer-0 generic syslog read is what saw it (via `includes:` in signals.yaml).
"""
from __future__ import annotations

import functools

from .select import issues_confirming
from .signals import load_signals

#: Layer 0 is the device/platform plane, not "below layer 1" — it sorts after the network
#: stack rather than before it. A missing layer sorts with it.
_DEVICE_PLANE = 99


def is_fault(signal: str | None) -> bool:
    """Is this signal a FAULT, as opposed to a health or context reading?

    Derived from whether any SOP issue confirms it — the same criterion the model's
    escalation menu and `includes:` both use, so there is one definition of "fault" and
    no flag to keep in sync.
    """
    return bool(signal) and bool(issues_confirming(signal))


@functools.lru_cache(maxsize=1)
def _home() -> dict[str, tuple[int, int]]:
    """signal -> (layer, declaration index) of the capability that DECLARES it.

    Built from the capability that owns the signal rather than the one that read it,
    because `includes:` lets a generic read match a domain's fault: read through
    `check-syslog-errors` (layer 0), `ospf-log-mtu-mismatch` is still a layer-3 OSPF
    fault, and ranking it as device-plane would put it below every routing reading.
    """
    out: dict[str, tuple[int, int]] = {}
    for cap, spec in load_signals().items():
        # `includes` splices another capability's signals in at load time; those are not
        # declared here and must not claim this capability's layer.
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
    """signal -> the signals it EXPLAINS, from `explains:` in signals.yaml.

    A causal edge between SIGNALS, which is where the relationship actually lives. The
    old machinery tried to express this as `excludes` between ISSUES, and that is what
    made a healthy adjacency delete a proven duplicate router-id: exclusion says "this
    cannot be true", when what we mean is "this is downstream of that".
    """
    out: dict[str, set[str]] = {}
    for spec in load_signals().values():
        for sig in spec.get("signals") or []:
            name, ex = sig.get("name"), sig.get("explains") or []
            if name and ex:
                out.setdefault(name, set()).update(ex)
    return {k: frozenset(v) for k, v in out.items()}


def rank(trail: list[dict]) -> dict:
    """Split a run's trail into the root cause, its symptoms, and the health readings.

    Returns {root_cause, symptoms, findings, health} where `root_cause` is a trail entry
    or None. None means nothing was PROVEN — not that the device is healthy.
    """
    # ONE FINDING PER SIGNAL, however many reads proved it. `includes:` deliberately lets
    # the generic log read match a domain fault, so the same line is matched by both
    # `check-ospf-logs` and `check-syslog-errors` — and the command cache feeds both from
    # one device round-trip. Without dedup the second row became an "also found", so a
    # single MTU mismatch was reported as the root cause AND as a second independent
    # fault, twice over. Keep the best-ranked read of each signal; it carries the quote.
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
        # A log line the DEVICE emitted is its own testimony; a table we interpreted is
        # our reading. `event_source` is set by the log parser, so this is a fact about
        # the record rather than a guess about the signal.
        device_named = 0 if t.get("event_source") == "device" else 1
        return (layer, device_named, spec_index, sig)

    primary_pool = [t for t in findings if t["signal"] not in explained] or findings
    ordered = sorted(primary_pool, key=key)
    root = ordered[0]

    # THREE BUCKETS, NOT TWO. Everything non-primary used to be called a symptom, and on
    # a device with a down link AND a duplicate router-id that labelled the duplicate
    # router-id a symptom of the link — a causal claim nothing in the SOP makes, and one
    # that would send an engineer to the wrong device. A finding is a symptom only when
    # another finding actually EXPLAINS it; otherwise it is a second, independent fault
    # and has to be reported as one.
    symptoms = [t for t in findings if t is not root and t["signal"] in explained]
    also = [t for t in findings if t is not root and t["signal"] not in explained]
    return {"root_cause": root,
            "symptoms": sorted(symptoms, key=key),
            "also": sorted(also, key=key),
            "findings": sorted(findings, key=key),
            "health": health}


def fault_signals(capability: str) -> frozenset[str]:
    """The FAULT signals a capability can produce (health/context readings excluded)."""
    spec = load_signals().get(capability) or {}
    return frozenset(s["name"] for s in (spec.get("signals") or [])
                     if s.get("name") and is_fault(s["name"]))


def outrankers(primary: str | None, unrun: set[str]) -> set[str]:
    """Which of `unrun` could still change WHICH finding is primary.

    Used to NARROW the pool once something is proven, not merely to decide when to stop.
    Without it a cold start asked every capability with a signal contract — on
    one lab router that was 20+ rounds at ~20s each and the request died on nginx's 300s
    gateway timeout, having already proven the duplicate router-id on round 4. Once a
    fault is proven, the only questions still worth asking are the ones that could beat
    it; everything else is device time spent on an answer that cannot move.
    """
    if primary is None:
        return set(unrun)
    plevel = layer_of_signal(primary)
    explainers = {s for s, ex in _explains().items() if primary in ex}
    return {cap for cap in unrun
            if any(sig in explainers or layer_of_signal(sig) < plevel
                   for sig in fault_signals(cap))}


def could_outrank(primary: str | None, unrun: set[str]) -> bool:
    """Could any not-yet-run check still change WHICH finding is primary?

    This is the early stop, and it exists because "collect everything, then rank" made a
    proven layer-1 fault wait for the rest of the pool: an administratively shut port is
    the most fundamental thing a device can tell us, and nothing below layer 1 exists to
    explain it. Continuing to probe after that is device time spent on an answer that
    cannot move.

    A check can only take the primary slot two ways — by producing a finding at a LOWER
    layer, or one that EXPLAINS the current primary. If no unrun check can do either, the
    ranking is final.

    The trade-off is deliberate and worth stating: stopping here may leave an INDEPENDENT
    fault at the same or a higher layer undiscovered. The primary is what an operator acts
    on, it is already proven, and a second unrelated fault surfaces on its own alert.
    """
    if primary is None:
        return True                       # nothing proven yet, so anything could change it
    plevel = layer_of_signal(primary)
    explainers = {s for s, ex in _explains().items() if primary in ex}
    for cap in unrun:
        for sig in fault_signals(cap):
            if sig in explainers or layer_of_signal(sig) < plevel:
                return True
    return False
