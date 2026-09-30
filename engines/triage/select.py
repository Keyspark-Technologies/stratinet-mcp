"""Narrowing: which check to run next, and which issues survive the answer.

The funnel is not authored — it already exists in the catalog. Checks are shared
across issues, and that sharing IS the tree. Measured on the 538-issue catalog:
484 (90%) have a unique check fingerprint; after one check ~3.8 candidates remain,
after two ~1.1, and 95% of check-PAIRS identify exactly one issue.

So there are no issue->issue edges to maintain. The path is computed per incident
and rendered afterwards as an explanation. Nothing here calls a model.
"""
from __future__ import annotations

import collections
import functools
from pathlib import Path

import yaml

from server.data import data_dir

from .signals import cost_of, is_systemic, load_signals

def _sop_dir() -> Path:
    return data_dir() / "sop"

#: Load only SOPs marked `verified: true` on the issue block.
#:
#: 534 of the 538 were generated in bulk and never checked against a device: signals
#: existed for 19 of 677 check capabilities, 79 are collapsed buckets merging 253
#: distinct causes, and only 5 of 49 live alert rules reached any SOP at all. A large
#: unverified catalog reads as coverage and is not — four SOPs that produce a proven
#: root cause are worth more than 538 that produce a plausible one.
#:
#: They stay in `issues/` rather than moving to a parked directory, so the corpus is
#: still readable: the structural tests (unique check fingerprints, no decision steps,
#: the signal index) assert properties of all 538 files, and those properties still
#: matter because the files are coming back one at a time.
#:
#: Unparking is per-SOP and is the LAST step of verification, not the first — see
#: docs/SOP_VERIFICATION.md.
ONLY_VERIFIED = True


def _is_verified(iss: dict) -> bool:
    return bool(iss.get("verified")) if ONLY_VERIFIED else True

@functools.lru_cache(maxsize=1)
def _index() -> tuple[dict[str, frozenset[str]], dict[str, frozenset[str]]]:
    """Build both directions of the check<->issue index from the diagnostic SOPs."""
    check_issues: dict[str, set[str]] = collections.defaultdict(set)
    issue_checks: dict[str, set[str]] = {}
    for path in (_sop_dir() / "issues").glob("*.yaml"):
        doc = yaml.safe_load(path.read_text()) or {}
        iss = doc.get("issue") or {}
        issue = iss.get("key")
        if not issue or not _is_verified(iss):
            continue
        procs = doc.get("procedures") or ([doc["procedure"]] if doc.get("procedure") else [])
        caps = {s["capability"] for p in procs for s in (p.get("steps") or [])
                if s.get("kind") == "check" and s.get("capability")}
        issue_checks[issue] = caps
        for c in caps:
            check_issues[c].add(issue)
    return ({k: frozenset(v) for k, v in check_issues.items()},
            {k: frozenset(v) for k, v in issue_checks.items()})


@functools.lru_cache(maxsize=1)
def _signal_index() -> tuple[dict[str, frozenset[str]], dict[str, frozenset[str]]]:
    """signal -> issues that CONFIRM it, and signal -> issues it EXCLUDES.

    Read from the issue block. This is what gives the signal VALUE its narrowing power:
    without it `routes-present` and `no-default-route` eliminate identically despite
    meaning opposite things.
    """
    confirms: dict[str, set[str]] = collections.defaultdict(set)
    excludes: dict[str, set[str]] = collections.defaultdict(set)
    for path in (_sop_dir() / "issues").glob("*.yaml"):
        doc = yaml.safe_load(path.read_text()) or {}
        iss = doc.get("issue") or {}
        key = iss.get("key")
        if not key or not _is_verified(iss):
            continue
        # Read from the ISSUE BLOCK only. `decision` steps are gone — they named a
        # capability that executed nothing and carried only these two lists, so the
        # lists moved up and the step was deleted (531 files, index proven unchanged:
        # 56 signals, 99 confirm and 84 exclude edges identical before and after).
        for k, sink in (("confirms", confirms), ("excludes", excludes)):
            for s in iss.get(k) or []:
                sink[s].add(key)
    return ({k: frozenset(v) for k, v in confirms.items()},
            {k: frozenset(v) for k, v in excludes.items()})


def issues_confirming(signal: str) -> frozenset[str]:
    return _signal_index()[0].get(signal, frozenset())


def issues_excluding(signal: str) -> frozenset[str]:
    return _signal_index()[1].get(signal, frozenset())


def all_issues() -> frozenset[str]:
    return frozenset(_index()[1])


def issues_for_check(check: str) -> frozenset[str]:
    return _index()[0].get(check, frozenset())


def checks_for_issue(issue: str) -> frozenset[str]:
    """The checks this issue's SOP names — the ones that could PROVE it.

    The inverse direction of `issues_for_check`, and it exists because elimination and
    confirmation are DIFFERENT selection objectives. `next_check` asks "which check best
    separates these candidates" and correctly returns None at one candidate, since there
    is nothing left to separate. But one surviving candidate is not a verdict — a root
    cause needs a confirming signal — and the checks that could supply one are exactly
    this set.

    Without it the loop stopped at `ospf-neighbor-down` with `check-ospf-neighbor` and
    `check-ospf-logs` never run, on a device whose OSPF table said EXCH START and whose
    log said `DD MTU is too large` forty times.
    """
    return _index()[1].get(issue, frozenset())


# ELIMINATION IS GONE — `_COST`, `_PRIOR`, `_expected_remaining`, `next_check` and
# `eliminate` were deleted with the candidate set they served. See findings.py for the
# measurement behind it: over one day of real faults, four of seven bugs came from this
# machinery and none from the evidence, and 467 of 539 issue files (86%) carried no
# confirming signal, so they could never be a verdict — only ever be eliminated.
#
# What stays is the read-only INDEX over the catalog: which checks an issue names, which
# issues confirm a signal, what layer a capability reads at. Ranking needs all three;
# nothing narrows a set any more.


def layer_of(capability: str) -> int | None:
    """The OSI layer a check reads at, from signals.yaml. Used to tell the model which
    layer each option sits at — a down interface explains a failed adjacency, never the
    reverse, and that ordering is worth stating rather than hoping it infers."""
    from .signals import load_signals
    spec = load_signals().get(capability) or {}
    v = spec.get("layer")
    return int(v) if isinstance(v, (int, str)) and str(v).isdigit() else None


#: Systemic checks worth asking first, most-likely-to-explain first. Hand-ordered, and
#: NOT derived from alert_events: 55,040 of 55,387 events there are one flapping OSPF
#: rule, so that distribution is a lab artefact.
_OPENING_ORDER = ("check-interface-state", "check-syslog-errors", "check-routing-table",
                  "check-ospf-neighbor", "check-lldp-neighbors")


def opening_checks(limit: int = 4) -> list[str]:
    """Cheap systemic checks to open with, before the domain's own questions.

    A down interface explains almost anything downstream of it, so it is asked first —
    on a real fault, ranking by information gain instead opened with check-routing-table,
    never looked at the interface, and concluded `ping-failure` on an admin-shut port.
    """
    sysn = [c for c in load_signals() if is_systemic(c) and cost_of(c) == "cheap"]
    rank = {c: i for i, c in enumerate(_OPENING_ORDER)}
    return sorted(sysn, key=lambda c: (rank.get(c, 99), c))[:limit]
