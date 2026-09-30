"""Evidence-driven triage — one stateless step at a time.

The brain deliberately has NO dispatch path: it cannot SSH, and that is a safety
property worth keeping. So this does not run commands. It answers two questions,
and the caller does the running:

    "what should I run next?"     -> next.capability + next.command, resolved per vendor
    "here is what it returned"    -> facts, signal, quoted evidence, narrowed candidates

Call it with no observations to get the first check; call it again with that
check's output to get the signal and the next check. Stateless — the caller
carries the observations, so nothing here holds per-incident state.

Narrowing is arithmetic over the catalog (see select.py). No model chooses a
check, a cause, or a fix.
"""
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
    """Fill {slots} from params. A slot is fillable only if it's in `allowed` (the catalog
    row's declared params) AND present in params. Returns (command, missing_slots).
    Injection guard: a template slot not in `allowed` is treated as missing (unsafe)."""
    slots = [f for _, f, _, _ in string.Formatter().parse(template) if f]
    missing = sorted({
        s for s in slots
        if s not in allowed or s not in params or params[s] in (None, "")
    })
    if missing:
        return template, missing
    return template.format(**{s: params[s] for s in slots}), []

#: Circuit breaker on planned steps. Not the stopping
#: condition — a run ends when a signal confirms a candidate, or when no unrun check
#: could change the answer. Each capability is asked at most once (`ran`), so a run
#: terminates naturally after the number of runnable checks; this only catches the case
#: where that bookkeeping is broken.
MAX_STEPS = 25


def _signal_means(signal: str) -> str:
    """The catalog's plain-English description of a signal, or "".

    `interface-log-went-down` is a catalog key. It is precise, and it is also
    what an operator sees as the headline of the whole diagnosis. The catalog
    already carries a sentence for every signal ("a log line records this
    interface changing to a down state"); it was only ever used to build model
    prompts. Returning it lets the console lead with the finding and keep the
    key as secondary detail.
    """
    for spec in (load_signals() or {}).values():
        for sig in (spec.get("signals") or []):
            if sig.get("name") == signal:
                return sig.get("means") or ""
    return ""


def _start_pool(issue: str | None) -> tuple[frozenset[str], str]:
    """Seed the pool of CHECKS worth running, from whatever the caller knows.

    Replaces the candidate set of ISSUES. Nothing is eliminated any more, so there is no
    set to narrow — what the alert tells us is which QUESTIONS are worth asking, and the
    answers are collected as findings and ranked (see findings.py for why).
    """
    if issue:
        checks = checks_for_issue(issue)
        if checks:
            return checks, f"issue named: {issue}"
    # Nothing to scope by: everything with a signal contract is fair game, and the
    # systemic openers still go first.
    pool = frozenset(load_signals())
    return pool, "no issue — asking broadly"


#: The catalog and the signals name  the same thing differently, and the mismatch made whole
#: steps vanish: a command needing `{ifname}` could never be filled because signals bind
#: `port`. Measured across the verified issues, SIX steps in FOUR procedures were skipped
#: this way — including `check-ospf-interface`, which is the reference SOP's entire §9.3.4
#: parameter comparison (MTU, area, timers, network type, auth) and §9.3.5 MTU check.
#:
#: Aliasing here rather than renaming 1,453 catalog rows or every signal's `binds`, both of
#: which are far larger edits with far more ways to go wrong.
_PARAM_ALIAS = {
    "port":         ("ifname",),
    "interface":    ("ifname", "ospf_if"),
    # NOT `peer` -> `peer_ip`: `peer` is the OSPF router-id and is frequently unreachable.
    # `peer_address` is the neighbour's interface address, which is the pingable one.
    "peer_address": ("peer_ip",),
}


def _with_aliases(binds: dict) -> dict:
    """Bound fields plus the catalog's names for the same values."""
    out = dict(binds)
    for src, targets in _PARAM_ALIAS.items():
        if binds.get(src):
            for t in targets:
                out.setdefault(t, binds[src])
    return out


@functools.lru_cache(maxsize=64)
def _clause_order(issue: str | None) -> dict[str, tuple[int, int]]:
    """capability -> (phase, clause) from the reference SOP, for ORDERING the pool.

    THE DOCUMENT'S ORDER IS A DIAGNOSTIC ARGUMENT, not presentation. §9.3 walks physical
    upward — interface, layer 2, hellos, parameters — because each step rules out a whole
    class of cause before the next one is worth asking, and skipping ahead means chasing a
    protocol fault on a link that was never up.

    Ours did not follow it. Sorting by cost then OSI layer put `check-routing-table` —
    which is §9.5.3, a VERIFY step — second in a real run, before most of §9.3 had
    happened. Verifying the fix before diagnosing the fault is not a different-but-valid
    order; it is the wrong order.

    Phase is taken from the clause itself: `9.3.x` diagnoses, `9.5.x` verifies. A step with
    no clause sorts after every mapped one rather than at the front, because an unmapped
    capability is one nobody has placed in the procedure yet.
    """
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
            # (9, 3, 1) -> phase 3, clause 1. Phase first so every 9.3.x precedes 9.5.x.
            phase = parts[1] if len(parts) > 1 else 9
            step = parts[2] if len(parts) > 2 else 0
            prev = out.get(cap)
            if prev is None or (phase, step) < prev:
                out[cap] = (phase, step)
        return out
    return {}


async def _peer_read_request(local_records: dict, observations: list,
                             vendor: str, trail: list) -> dict | None:
    """The far-end read, when a `differs` comparison has only one side.

    `differs` signals (MTU, area, timers, network type, auth, duplex, native VLAN) are
    the SOPs' most-cited diagnostic — SOP-LAN-010 §9.3.1 and SOP-LAN-002 §9.3.1 both
    OPEN with "compare both ends side by side", and SOP-INT-007 refers to it 21 times.
    With one side they return healthy on a misconfigured link.

    The two blockers that kept this unimplemented are both addressed:

      THE PEER COMMAND NEEDED `{ifname}`, which only a fault signal binds — and on the
      case that matters most, no adjacency at all, no fault fires so nothing binds it.
      Solved by asking the peer for ALL its interfaces: `show ip ospf interface` with no
      argument is valid on every vendor that has the parameterised form.

      THE PEER'S INTERFACE NAME IS NOT OURS — dr02 Ethernet5 faces ar02 Ethernet1 — so
      filling `{ifname}` with the local name read a different link. Solved in
      `signals._differing_pair`, which pairs the two sides by SHARED SUBNET and stays
      silent when no pairing is justified.

    WHO the peer is comes from LLDP, not from the protocol under investigation. A timer
    or area mismatch means there IS no adjacency, so there is no neighbour address to
    read — but the cable is still there and LLDP still answers. That is also what an
    engineer does: ask what is on the other end of this port.

    Returns a step the CALLER executes, like every other step; this function asks, it
    does not connect. `origin: "peer"` is the contract that makes the returned
    observation merge into the local set rather than replace it.
    """
    from .signals import _link_key
    needs_peer = [cap for cap in _compares_both_ends() if local_records.get(cap)]
    if not needs_peer:
        return None
    already = {(o.get("capability") or "") for o in observations
               if (o.get("origin") or "local").lower() == "peer"}
    cap = next((c for c in sorted(needs_peer) if c not in already), None)
    if cap is None:
        return None

    # The local side must carry an address, or nothing can be paired when the answer
    # arrives and the read would be spent for a comparison that cannot be made.
    subnets = [k for r in local_records[cap] if (k := _link_key(r))]
    if not subnets:
        return None

    # WHO. An LLDP read already in the trail names the neighbour; otherwise ask for it
    # first — one extra round, and it is the only thing that works with no adjacency.
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
            return None            # asked already and it named nobody — do not loop
        return {"capability": "check-lldp-neighbors", "command": lldp.command,
                "description": "identify the device on the far end of the link",
                "why": f"{cap} compares both ends and only ours has been read; LLDP names "
                       "the far end without needing the protocol to be up",
                "selected_by": "both-ends comparison needs a peer", "missing_params": []}

    vcmd = command_for(cap, vendor)
    if not vcmd:
        return None
    # UNPARAMETERISED: ask for every interface and pair by subnet on the way back.
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
    """Capabilities carrying a `differs` signal — the ones a single device cannot answer.

    A mismatch is invisible from one end: 1500 is not wrong, it is only wrong opposite
    1400. These capabilities therefore need the SAME read from the far end before any of
    their comparisons can say anything, and until the engine asks for it they return
    `healthy` on a link that is misconfigured.

    That silence is not theoretical. Across the whole fleet over 24 hours there were ZERO
    OSPF log lines, so the log path — the only other way these faults surface — had nothing
    to offer either. A wrong hello timer would simply never form an adjacency, and nothing
    anywhere would say why.
    """
    from .signals import load_signals
    return frozenset(cap for cap, spec in load_signals().items()
                     if any("differs" in s for s in (spec.get("signals") or [])))


async def triage(session, req: dict, *, deterministic: bool = True) -> dict:
    """One stateless triage step. See the module docstring for the contract."""
    if not deterministic:
        raise ValueError("only the deterministic mode is available")
    vendor = req.get("vendor")
    observations = req.get("observations") or []
    params = dict(req.get("params") or {})

    pool, entry = _start_pool(req.get("issue"))
    #: The issue whose PROCEDURE orders the pool. Its reference SOP walks §9.3 physical
    #: upward for a reason — each step rules out a class of cause before the next is worth
    #: asking — and that argument is lost if we sort by our own cost heuristic.
    seed_issue = req.get("issue")
    trail: list[dict] = []
    ran: set[str] = set()
    #: command -> the output it already produced this run. Several capabilities resolve
    #: to the SAME command (244 such pairs in the catalog; one FortiSwitch command serves
    #: 29 capabilities), and the loop was spending a round on each: a real run went
    #: `check-policy-match -> show ip access-lists` then
    #: `check-security-policy-match -> show ip access-lists`, two of six rounds on one
    #: output. A second capability now reads the output we already have, for free.
    seen_output: dict[str, str] = {}
    #: capability -> the records its LOCAL read produced. A mismatch is not visible from
    #: one end — "1500 is not wrong, it is only wrong opposite 1400" — so `differs` needs
    #: both ends in ONE record set. Every `differs` signal in the catalog (7 of them,
    #: covering their §9.3.4 parameter table) was structurally unable to fire because
    #: nothing ever supplied the far side.
    local_records: dict[str, list[dict]] = {}

    # Replay what the caller has already collected, in order. Each observation
    # narrows, and its binds become params for whatever runs next.
    for obs in observations:
        cap = obs.get("capability")
        if not cap:
            continue
        ran.add(cap)
        if obs.get("error"):
            # The command did not run — wrong driver, auth failure, unreachable. That is
            # a fact about US, not about the device, and it must eliminate nothing. Left
            # to the normal path its empty output parses to `ok_empty`, which is a real
            # status several signals match ("no neighbours", "not configured"), so a
            # transport failure would read as a confident finding.
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
        # WHICH END produced this. `differs` compares one field across two records tagged
        # `local` and `peer`; absent the tag every record is local and the comparison can
        # never find a second side.
        origin = (obs.get("origin") or "local").strip().lower()
        for r in facts["records"]:
            r["_origin"] = origin
        if origin == "local":
            local_records[cap] = list(facts["records"])
        else:
            # A peer read is evaluated TOGETHER with the local one for that capability —
            # on its own it is just another device's healthy interface and says nothing.
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
            # which layer read it: a predicate, or a model reading the raw output
            "observed_by": (sig or {}).get("observed_by") or ("predicate" if sig else None),
            "predicate_signal": (sig or {}).get("predicate_signal"),
            # a FAULT, or a health/context reading? findings.py owns that distinction
            "is_fault": is_fault(sig["signal"]) if sig else False,
            "layer": layer_of_signal(sig["signal"]) if sig else layer_of(cap),
            # the log parser sets event_source; the ranking uses it to prefer a fault the
            # device named itself over one we inferred from a table
            "event_source": (facts.get("records") or [{}])[0].get("event_source")
                            if facts.get("records") else None,
            # an unreadable check is not evidence — say so rather than imply health
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
        """Rank what the run FOUND. See findings.py for why this replaced elimination."""
        return rank(trail)

    def _cannot_determine(reason: str) -> dict:
        """Nothing was PROVEN. Not the same claim as "the device is healthy"."""
        out["next"] = None
        out["escalate"] = reason
        out["cannot_determine"] = True
        return out

    async def _converge(v: dict) -> dict:
        """Name the cause from the ranked findings.

        THE SIGNAL IS THE CAUSE. `ospf-neighbor-down` is a FAMILY — fifteen different
        faults collapse onto it, because the catalog merged ospf-area-mismatch,
        ospf-authentication-mismatch and ospf-dr-bdr-election-problem into that one
        bucket. A signal is verifiable on one device with one command; an issue key is a
        label. So the top-ranked finding's signal is the cause, and the issue it belongs
        to is only the family it sits in.
        """
        root = v["root_cause"]
        cause = root["signal"]
        family = sorted(issues_confirming(cause))
        issue = family[0] if family else cause
        out["root_cause"] = {
            "cause": cause,
            "means": _signal_means(cause),
            "issue": issue,
            "evidence": [root],
            # Symptoms are findings another finding EXPLAINS — real, and not the thing to
            # go and change. `also` are independent faults: a down link does not cause a
            # duplicate router-id, and calling one a symptom of the other would send an
            # engineer to the wrong device.
            "symptoms": [{"cause": t["signal"], "evidence": t.get("evidence"),
                          "capability": t.get("capability")} for t in v["symptoms"]],
            "also_found": [{"cause": t["signal"], "evidence": t.get("evidence"),
                            "capability": t.get("capability")} for t in v["also"]],
            # NOT `[cause]`. Under elimination this listed the signals that confirmed a
            # surviving ISSUE, so cause and confirmer were different strings and the line
            # meant something. Now the signal IS the cause, so echoing it rendered as
            # "ROOT CAUSE ospf-log-duplicate-router-id / confirmed by
            # ospf-log-duplicate-router-id" — a tautology where an operator expects the
            # proof. What proved it is the command and the line it returned.
            "proved_by": {"capability": root.get("capability"),
                          "command": root.get("command"),
                          "line": root.get("evidence"),
                          "read_by": root.get("observed_by"),
                          # carried here so the rendered verdict is self-sufficient from
                          # `proved_by` alone — a replay has no trail row to read it off
                          "layer": root.get("layer")},
            "decided_by": "evidence — signals over extracted facts, no model",
        }
        out["next"] = None
        return out

    v = _verdict()
    out["findings"] = [t["signal"] for t in v["findings"]]
    out["finding_count"] = len(v["findings"])

    # EARLY STOP. Nothing unrun could take the primary slot — no lower layer to reach and
    # nothing that explains it — so the ranking is already final and further probing is
    # device time spent on an answer that cannot move.
    _unrun = {c for c in pool if c not in ran and shape_of(c) is not None}
    if v["root_cause"] and not could_outrank(v["root_cause"]["signal"], _unrun):
        return await _converge(v)

    # RUN THE POOL TO EXHAUSTION, THEN RANK.
    #
    # Stopping at the first fault found would report a layer-3 symptom while never
    # reading the layer-1 interface that explains it — ranking cannot be right until
    # collection is finished. The round budget is the circuit breaker, not the stopping
    # condition, and the command cache means several capabilities often cost one round.
    if len(trail) >= MAX_STEPS:
        out["next"] = None
        out["escalate"] = (f"stopped after {len(trail)} checks (budget) — "
                           f"{out['finding_count']} finding(s); hand to an engineer")
        return out

    #: Cheap questions before expensive ones, when nothing else ranks them.
    _COST_ORDER = {"cheap": 0, "moderate": 1, "expensive": 2}

    skipped: list[dict] = []
    deferred: list[dict] = []      # better checks blocked only on a missing param
    runnable: list[dict] = []      # every option we could actually run, for the model
    tried = set(ran)

    # SYSTEMIC checks first. A down interface explains almost anything downstream of it,
    # so it is asked before the domain's own questions — and on a real fault that
    # ordering was the difference between naming an admin-shut port and concluding
    # `ping-failure` with "correct-firewall-policy".
    # ONCE SOMETHING IS PROVEN, ASK ONLY WHAT COULD BEAT IT. A cold start has no alert to
    # scope by, so the pool is every capability with a signal contract — 20+ rounds at
    # ~20s, which on a lab router exceeded nginx's 300s gateway timeout having already
    # proven the duplicate router-id on round 4.
    # THE SOP'S ORDER FIRST. Cost and layer only break ties among steps the document does
    # not place — they used to be the whole key.
    _clauses = _clause_order(seed_issue)
    _primary = (v["root_cause"] or {}).get("signal")
    askable = pool if _primary is None else (
        pool & (outrankers(_primary, set(pool)) | set(opening_checks())))

    # SYSTEMIC OPENERS COVER WHAT THE PROCEDURE DOES NOT PLACE — nothing more.
    #
    # `opening_checks()` is a global "ask these first" list and it earns its place: a down
    # interface explains almost anything downstream, and ranking purely by information gain
    # once opened with check-routing-table, never looked at the interface, and concluded
    # `ping-failure` on an admin-shut port.
    #
    # But where the SOP DOES place a capability, its authors have already decided when to
    # ask it, and overriding that reorders their argument. Measured across the twelve
    # implemented issues, this list alone put three runs out of order:
    #   control-plane-resource-exhaustion  §9.3.5 logging before §9.3.1 identify the consumer
    #   vlan-down-or-missing               §9.3.2 trace the path before §9.3.1 the VLAN database
    #   ospf-neighbor-down                 §9.5.3 verify before §9.3 had diagnosed anything
    # So a capability the procedure places is ordered by its clause; the openers only lead
    # for capabilities the document says nothing about — including every broad run, where
    # there is no procedure and the safety net is the whole point.
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
            continue                      # no signal contract — its output is unreadable
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

        # Already have this exact output? Read it now rather than spend a round on it.
        # Capabilities are not one-to-one with commands — `check-router-id` and
        # `check-ospf-config` are BOTH `show ip ospf` — and extraction is local, so the
        # same text can serve a different shape at no device cost.
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
                "reused": cmd,      # no device round-trip was spent on this
                "note": None if sig else "output unreadable — no finding",
            })
            v = _verdict()
            out["trail"], out["params"] = trail, params
            out["steps_taken"] = len(trail)
            out["findings"] = [t["signal"] for t in v["findings"]]
            out["finding_count"] = len(v["findings"])
            continue

        if missing:
            # Report it rather than silently settling for a weaker check: the caller can
            # often resolve a param we cannot (an SNMP label that outlived the series, or
            # the device's own config), and it retries with those params bound.
            deferred.append({"capability": cap, "command_template": vcmd.command,
                             "needs": missing})
            skipped.append({"capability": cap,
                            "why": f"needs params not bound yet: {missing}"})
            continue
        step["command"] = cmd
        step["missing_params"] = []
        step["description"] = getattr(vcmd, "description", None) or _describe(cap)
        # Collect every runnable option instead of taking the first, so the model sees
        # the whole menu alongside the evidence gathered so far.
        runnable.append(step)

    if runnable:
        step = runnable[0]
        step["selected_by"] = ("no choice — one option" if len(runnable) == 1
                               else "first in the procedure order")
        step["menu"] = [s["capability"] for s in runnable]
        if skipped:
            step["skipped"] = skipped      # say what was passed over and why
        if deferred:
            out["deferred"] = deferred     # resolve these params and ask again
        out["next"] = step
        return out

    # THE POOL IS EXHAUSTED locally. Before ranking, ASK THE FAR END if a comparison is
    # waiting on it — a `differs` signal with one side reports healthy on a misconfigured
    # link, and the reference SOPs open their mismatch procedures with exactly this read.
    # See `_peer_read_request` for how the two old blockers are handled.
    if (peer_step := await _peer_read_request(local_records, observations,
                                              vendor or "", trail)):
        out["next"] = peer_step
        if deferred:
            out["deferred"] = deferred
        return out

    # Was unreachable: it sat after `return out` inside `if runnable:`, so on the
    # pool-exhausted path `deferred` was silently never reported to the caller.
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
