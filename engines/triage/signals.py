"""Evaluate signal predicates over extracted facts.

Deterministic and pure: no I/O, no model, no device. A signal is a named
observation; the first one in declaration order that fits wins, so ordering is
precedence. `binds` lifts canonical fields off the matching record so the next
check gets its parameters without anyone typing them.

Guard rails learned from real output:
  - an empty `records` list can never satisfy `none:` — otherwise "nothing
    found" silently becomes a finding, which is how a populated
    `Default gateway is 10.0.0.1` output got called `no-default-route`.
  - `unparseable` yields no signal at all: the engine must ask again, not guess.
"""
from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

import yaml

from server.data import data_dir

def _sop_dir() -> Path:
    return data_dir() / "sop"

# A status that means "we could not read this" — never infer a signal from it.
_BLIND = {"unparseable", "error"}


def _confirms_an_issue(name: str | None) -> bool:
    """Does any SOP issue CONFIRM this signal — i.e. is it a fault rather than a health
    or context reading? Imported lazily because select.py reads signals.yaml itself, and
    a module-level import would be circular."""
    if not name:
        return False
    from .select import issues_confirming
    return bool(issues_confirming(name))


@functools.lru_cache(maxsize=1)
def load_signals() -> dict[str, dict]:
    """Capability -> signal contract, with `includes:` spliced in.

    `includes: [check-ospf-logs, ...]` prepends another capability's signals to this
    one's. It exists because the GENERIC log read was throwing away answers the
    domain-specific signals would have caught.

    On a lab router the run reached `check-syslog-errors`, whose output contained

        %OSPF-4-OSPF_ROUTER_LSA_REORIG: Duplicate Router ID 1.1.1.1 detected in area 0.0.0.0

    and reported `log-clean` — then NO FAULT FOUND. The OSPF log signals were authored
    on `check-ospf-logs`, a different capability that this run never selected, so the
    line was parsed, quoted as evidence, and read against a signal list that had nothing
    to say about it. The two capabilities parse identically (`log_lines`); only the
    consulted signals differed.

    Prepending rather than appending matters: a named fault must beat the generic
    severity readings and `log-clean`, since the first signal that fits wins. And
    `includes` also fills the model's fault menu for the generic read, which was empty —
    so an unpredicted wording had no escalation path there either.
    """
    doc = yaml.safe_load((_sop_dir() / "signals.yaml").read_text()) or {}
    specs = {k: v for k, v in doc.items() if isinstance(v, dict)}
    for cap, spec in specs.items():
        inc = spec.get("includes") or []
        if not inc:
            continue
        # FAULT SIGNALS ONLY. Borrowing a domain's whole list also borrows its
        # fall-through, and prepending that preempts the generic readings: a FortiOS
        # `level="alert" logdesc="Admin login failed"` line stopped matching
        # `critical-logged` and started matching `interface-log-quiet`, the interface
        # domain's own "nothing to report". A capability may borrow another's knowledge
        # of what a FAULT looks like; it must never borrow its verdict of health.
        #
        # "Fault" is not a flag to maintain — it is whether the SOP catalog has an issue
        # that CONFIRMS the signal, the same criterion the model's escalation menu uses.
        borrowed: list[dict] = []
        for other in inc:
            src = specs.get(other) or {}
            if src.get("shape") != spec.get("shape"):
                # Signals are predicates over a SHAPE's fields. Borrowing across shapes
                # would evaluate `state` against a log record and quietly never match.
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
    """The SUBNET the two ends of a link share — the only reliable way to pair them.

    Interface NAMES cannot do it: dr02 `Ethernet5` faces ar02 `Ethernet1`, so pairing by
    name compares unrelated links. The addresses can: 10.12.3.1/30 and 10.12.3.2/30 are
    both 10.12.3.0/30, and two interfaces sharing a subnet are by definition the two ends
    of one link.

    Returns None when the record carries no address — which makes the record unpairable
    rather than wrongly paired, and `_differing_pair` treats that as "cannot tell".
    """
    addr, plen = rec.get("address"), rec.get("prefix_len")
    if not addr or plen in (None, ""):
        return None
    try:
        import ipaddress
        return str(ipaddress.ip_network(f"{addr}/{plen}", strict=False))
    except ValueError:
        return None


def _differing_pair(sig: dict, records: list[dict]) -> tuple[dict, dict] | None:
    """The (local, peer) pair that disagrees on the field, or None.

    `differs: {field: area, between: [local, peer]}` — every other predicate form tests
    one field of one record, but most OSPF and layer-2 causes (MTU, area, timers, network
    type, auth, duplex, native VLAN) are MISMATCHES that cannot be seen from one end:
    1500 is not wrong, it is only wrong opposite 1400. The reference SOPs say so directly
    — SOP-LAN-010 §9.3.1 is "almost always visible immediately in a side-by-side
    comparison and almost always invisible when the ends are examined separately."

    PAIRED BY LINK, which is the fix. The previous form took the FIRST record per side
    (`vals.setdefault`), so on a router with several interfaces it compared local
    interface #1 against peer interface #1 — different links, unrelated parameters, and a
    confident mismatch between two interfaces that were never connected. That is worse
    than silence, and it is why this comparison was documented as not-implemented rather
    than merely unwired.

    Records are tagged `_origin` by the caller when a peer read supplies the second side.
    A missing side yields None, never a pair — we have not shown a mismatch, we have
    failed to look, and those must not read the same.
    """
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
    # NO SHARED SUBNET. Unambiguous only when each side offers exactly one record —
    # then there is one possible pairing and it needs no address to justify it. With
    # several on either side the correct pairing is unknown, and guessing one is the
    # error this function exists to prevent.
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

    # every remaining form is about records, so a blind read can never match
    if status in _BLIND:
        return False

    if "any" in sig:
        f, v = next(iter(sig["any"].items()))
        return any(_match(r, f, v) for r in records)

    if "none" in sig:
        f, v = next(iter(sig["none"].items()))
        # records must exist: absence is not evidence
        return bool(records) and not any(_match(r, f, v) for r in records)

    if "all" in sig:
        f, v = next(iter(sig["all"].items()))
        return bool(records) and all(_match(r, f, v) for r in records)

    if "count" in sig:
        op, n = next(iter(sig["count"].items()))
        c = len(records)
        return {"gt": c > n, "lt": c < n, "eq": c == n}.get(op, False)

    if "contains" in sig:
        # Substring match on a field — `contains: {message: "MTU mismatch"}`.
        # Vendor log messages carry the reason as prose inside one field:
        # `%OSPF-5-ADJCHG: ... from FULL to DOWN, Neighbor Down: Dead timer expired`
        # states the cause outright. Exact equality cannot reach it, and deriving a
        # `reason` field in the parser would move the vendor's wording into code — the
        # string we are matching IS domain knowledge and belongs in the SOP.
        f, want = next(iter(sig["contains"].items()))
        needle = str(want).strip().lower()
        return any(needle in str(r.get(f) or "").lower() for r in records)

    if "differs" in sig:
        return _differing_pair(sig, records) is not None

    if "field" in sig:
        # Numeric comparison on a named field: `field: {clash: {gt: 0}}`.
        # Counters are inherently numeric and the THRESHOLD is domain meaning — a
        # session clash above zero is what asymmetric routing looks like. That belongs
        # in the SOP where it can be read and argued with, not buried in the extractor
        # as a pre-derived boolean.
        # EVERY named field must hold, ON THE SAME RECORD. Before this, only the first
        # key was read and the rest were dropped in silence — the duplicate-YAML-key trap
        # again, where a signal reads as more specific than it evaluates. ANDing is also
        # what the SOP's scope question needs: "all adjacencies down on ONE DEVICE" is a
        # device fault, "one adjacency down" is a link fault, and the two differ only by
        # `peers_full == 0` AND `peers_total > 1` together.
        def _holds(r: dict) -> bool:
            for name, cmp in sig["field"].items():
                op, n = next(iter(cmp.items()))
                raw = r.get(name)
                if raw is None:
                    return False        # cannot show it; not the same as showing it false
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
    """The record that justifies the signal — the one params come from.

    `context` carries params already bound earlier in the run. Preferring a record
    that agrees with them matters: on a real induced fault the LLDP table bound
    {neighbor_name: ar05, local_interface: Ma0} — the MANAGEMENT port — because
    records[0] happened to be that one, while the fault was on Et1.
    """
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
            # A scope was set and nothing in this table belongs to it. Returning
            # cands[0] anyway bound the MANAGEMENT port's LLDP neighbour to an
            # incident about Et1 — params that read as related evidence but are not.
            # Better to bind nothing than to bind something irrelevant.
            return None
        return cands[0]

    # EVERY record-matching form, not just any/all. `contains` and `field` fell through
    # to records[0], so `ospf-log-mtu-too-large` quoted an %ACCOUNTING line recording our
    # own SSH login while the MTU line that actually proved the signal sat three rows
    # down. The signal was right and the evidence pointed somewhere else, which is worse
    # than no evidence — an operator reads the quoted line, not the slug.
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
        # Quote the line carrying the FIELD THAT DIFFERS, and prefer the PEER's — the far
        # end is the odd one out, and "Ethernet5 is up, line protocol is up (connected)"
        # as proof of an MTU mismatch is a health line under a fault heading, which is the
        # same defect the counter signals had.
        fld = (sig["differs"] or {}).get("field")
        # FROM THE PAIR THAT ACTUALLY DIFFERS. Taking any peer record carrying the field
        # quotes a different link than the one the signal fired on once more than one
        # interface is read — the finding would be right and its evidence would point at
        # an unrelated port.
        pair = _differing_pair(sig, records)
        if pair:
            local, peer = pair
            r = dict(peer)
            line = r.get(f"_line_{fld}")
            if line:
                r["_line"] = line
            # Both halves of the comparison, so the console can show the disagreement
            # rather than one number the reader has to take on trust.
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
        # Whole spec, not the first key — the evidence must be quoted from a record that
        # satisfies the SAME condition the signal fired on, or the line on screen does not
        # prove the finding above it.
        matched = [r for r in records if _fits({"field": sig["field"]},
                                               {"records": [r], "status": "ok"})]
        return _prefer(matched or records)

    # `none` matched nothing in the desired state, so any record is the problem;
    # `count`/`differs`/`status` are statements about the table, not about one row.
    return _prefer(records)


def evaluate(capability: str, facts: dict, context: dict | None = None) -> dict | None:
    """Return {signal, evidence, binds, source, follow_up} or None when nothing fits.

    None means "no signal" — the caller must run another check, never assume health.
    `context` is the params bound so far, used to pick the relevant record.
    """
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
        # Quote the line that JUSTIFIES the signal, not the first line of output —
        # for any table that is the column header, which is useless as evidence.
        #
        # For a `field:` signal the header is worse than useless, it CONTRADICTS the
        # finding: `interface-flapping` on a link that is up right now quoted
        # "Ethernet1 is up, line protocol is up (connected)" — a health line printed as
        # proof of a fault. A single-record shape like `interface_detail` has one `_line`,
        # and it cannot serve a dozen counters, so a reader may stash `_line_<field>` per
        # counter and the signal that fired on that counter quotes it.
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
    """One line of what this check looks at — shown to the model in the menu, so it can
    tell `check-ospf-interface` (area/timers/auth) from `check-ospf-neighbor` (state)."""
    spec = load_signals().get(capability) or {}
    return spec.get("description") or capability.replace("check-", "").replace("-", " ")


def cost_of(capability: str) -> str:
    spec = load_signals().get(capability) or {}
    return spec.get("cost", "moderate")


def is_systemic(capability: str) -> bool:
    return bool((load_signals().get(capability) or {}).get("systemic"))
