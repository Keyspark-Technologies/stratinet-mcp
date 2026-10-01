from __future__ import annotations

import collections
import functools
from pathlib import Path

import yaml

from server.data import data_dir

from .signals import cost_of, is_systemic, load_signals

def _sop_dir() -> Path:
    return data_dir() / "sop"

ONLY_VERIFIED = True


def _is_verified(iss: dict) -> bool:
    return bool(iss.get("verified")) if ONLY_VERIFIED else True

@functools.lru_cache(maxsize=1)
def _index() -> tuple[dict[str, frozenset[str]], dict[str, frozenset[str]]]:
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
    confirms: dict[str, set[str]] = collections.defaultdict(set)
    excludes: dict[str, set[str]] = collections.defaultdict(set)
    for path in (_sop_dir() / "issues").glob("*.yaml"):
        doc = yaml.safe_load(path.read_text()) or {}
        iss = doc.get("issue") or {}
        key = iss.get("key")
        if not key or not _is_verified(iss):
            continue
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
    return _index()[1].get(issue, frozenset())


def layer_of(capability: str) -> int | None:
    from .signals import load_signals
    spec = load_signals().get(capability) or {}
    v = spec.get("layer")
    return int(v) if isinstance(v, (int, str)) and str(v).isdigit() else None


_OPENING_ORDER = ("check-interface-state", "check-syslog-errors", "check-routing-table",
                  "check-ospf-neighbor", "check-lldp-neighbors")


def opening_checks(limit: int = 4) -> list[str]:
    sysn = [c for c in load_signals() if is_systemic(c) and cost_of(c) == "cheap"]
    rank = {c: i for i, c in enumerate(_OPENING_ORDER)}
    return sorted(sysn, key=lambda c: (rank.get(c, 99), c))[:limit]
