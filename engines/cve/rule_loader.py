"""Load hand-written exposure detectors from app/rules/detectors.toml.

Rules used to be Python dicts inside grounding.py, which meant adding one was surgery on the module
that decides every verdict. Moving them to a data file lowers that to a data edit while keeping the
property that actually matters: they live in git, so every detector has an author, a reviewer and a
diff. That is the thing the LLM rule generator never had, and the reason it produced 83 brittle
rules nobody had read.

Validation is strict and happens at import. A malformed rule file is a startup failure, not a
silently degraded scan -- a detector that quietly fails to load reads as "feature absent", which is
the false-clean this whole subsystem exists to prevent.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

RULES_PATH = Path(__file__).resolve().parents[1] / "rules" / "detectors.toml"

# How a NON-match is allowed to be interpreted. See the header of detectors.toml.
ABSENCE_MODES = ("clear", "detect", "proof")

# Keys that are not vendor detectors, so _detect() does not treat them as one.
_NON_VENDOR_KEYS = ("label", "absence_means", "vulnerable_commands", "fixtures",
                    "provenance", "absent_when", "hardened_when")


class RuleFileError(ValueError):
    """The rule file is malformed. Deliberately fatal."""


def _fail(where: str, msg: str) -> None:
    raise RuleFileError(f"{RULES_PATH.name}: [{where}] {msg}")


def _validate_feature(fid: str, spec: dict) -> None:
    if not isinstance(spec, dict):
        _fail(fid, "feature must be a table")
    if not (spec.get("label") or "").strip():
        _fail(fid, "missing label")

    mode = spec.get("absence_means")
    if mode not in ABSENCE_MODES:
        _fail(fid, f"absence_means must be one of {ABSENCE_MODES}, got {mode!r}. This decides "
                   f"whether a non-match may tell a device it is safe; it is not optional.")

    detectors = spec.get("detectors") or {}
    if not detectors:
        _fail(fid, "no detectors — a feature with no regex can never decide anything")
    for vend, rx in detectors.items():
        if not isinstance(rx, str) or not rx.strip():
            _fail(fid, f"detector for {vend!r} is empty")
        try:
            re.compile(rx)
        except re.error as e:
            _fail(fid, f"detector for {vend!r} does not compile: {e}")

    absent_when = spec.get("absent_when") or {}
    for vend, rx in absent_when.items():
        try:
            re.compile(rx)
        except re.error as e:
            _fail(fid, f"absent_when for {vend!r} does not compile: {e}")

    # hardened_when inverts the usual shape. Some advisories are not "exposed if you enabled X" but
    # "exposed unless you added Y" -- the vulnerable behaviour is the DEFAULT and the vendor's
    # workaround is a protective line you put in. CVE-2026-12546 is the largest single item in this
    # fleet's backlog and reads exactly that way: `ip software forwarding mtu exceed action drop`.
    #
    # Modelled without a new mode. The detector keeps its meaning -- it establishes that the
    # subsystem is present at all, i.e. that the CVE is in scope here -- and hardened_when decides
    # the verdict WITHIN that scope: present and hardened is safe, present and unhardened is
    # exposed. A device with no such subsystem falls through to absence_means as before.
    hardened_when = spec.get("hardened_when") or {}
    for vend, rx in hardened_when.items():
        try:
            re.compile(rx)
        except re.error as e:
            _fail(fid, f"hardened_when for {vend!r} does not compile: {e}")
        if vend not in detectors:
            _fail(fid, f"hardened_when for {vend!r} has no matching detector — without one there "
                       f"is no scope test, so every device would read as exposed")

    # "proof" means MITIGATED requires positive evidence the feature is off. Without absent_when
    # for the vendor being tested there is no such evidence, and the mode is a no-op that would
    # quietly behave like "detect".
    if mode == "proof":
        if not absent_when:
            _fail(fid, 'absence_means = "proof" requires an absent_when pattern — otherwise there '
                       'is nothing to prove absence with')
        missing = [v for v in detectors if v not in absent_when]
        if missing:
            _fail(fid, f'absence_means = "proof" but no absent_when for vendor(s) {missing}')

    fx = spec.get("fixtures") or {}
    # A hardened_when rule needs its own negative case: a config where the subsystem IS present and
    # the protective line IS there must NOT read as exposed. That is the whole point of the mode and
    # the one thing a plain must_not_match would not cover.
    if hardened_when and not fx.get("must_be_hardened"):
        _fail(fid, "hardened_when requires a must_be_hardened fixture — a config carrying both the "
                   "subsystem and the protective line, which must not read as exposed")
    if not fx.get("must_match"):
        _fail(fid, "no must_match fixture — an untested detector is how a brittle rule reaches a "
                   "device")
    if "must_not_match" not in fx:
        _fail(fid, "must_not_match missing (may be an empty list, but state it deliberately)")


def _validate_cves(cves: dict, features: dict) -> None:
    for cid, rule in cves.items():
        if not isinstance(rule, dict):
            _fail(cid, "cve entry must be a table")
        if rule.get("undecidable"):
            continue
        feats = rule.get("features") or []
        if not feats:
            _fail(cid, "neither features nor undecidable — this CVE decides nothing")
        for f in feats:
            if f not in features:
                _fail(cid, f"references unknown feature {f!r}")


def load_rules(path: Path | None = None) -> tuple[dict, dict]:
    """Return (features, cve_rules) in the shape grounding expects.

    features: {fid: {label, <vendor>: regex, vulnerable_commands, absence_means, absent_when, ...}}
    cve_rules: {CVE-ID: {features: [...]}} or {CVE-ID: {undecidable: "..."}}
    """
    p = path or RULES_PATH
    try:
        raw = tomllib.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise RuleFileError(f"{p} not found — there are no exposure rules to load")
    except tomllib.TOMLDecodeError as e:
        raise RuleFileError(f"{p.name}: not valid TOML: {e}") from e

    raw_features = raw.get("features") or {}
    raw_cves = raw.get("cves") or {}
    if not raw_features:
        _fail("features", "no features defined")

    features: dict = {}
    for fid, spec in raw_features.items():
        _validate_feature(fid, spec)
        flat: dict = {
            "label": spec["label"],
            "absence_means": spec["absence_means"],
            "vulnerable_commands": spec.get("vulnerable_commands") or {},
            "absent_when": spec.get("absent_when") or {},
            "hardened_when": spec.get("hardened_when") or {},
            "provenance": spec.get("provenance") or {},
            "fixtures": spec.get("fixtures") or {},
        }
        # Vendor regexes are flattened to top level so _detect can keep doing feat.get(vendor).
        for vend, rx in (spec.get("detectors") or {}).items():
            if vend in _NON_VENDOR_KEYS:
                _fail(fid, f"vendor name {vend!r} collides with a reserved key")
            flat[vend] = rx
        features[fid] = flat

    cve_rules = {str(k).strip().upper(): v for k, v in raw_cves.items()}
    _validate_cves(cve_rules, features)
    return features, cve_rules
