from __future__ import annotations

import re
import tomllib
from pathlib import Path

RULES_PATH = Path(__file__).resolve().parents[1] / "rules" / "detectors.toml"

ABSENCE_MODES = ("clear", "detect", "proof")

_NON_VENDOR_KEYS = ("label", "absence_means", "vulnerable_commands", "fixtures",
                    "provenance", "absent_when", "hardened_when")


class RuleFileError(ValueError):
    pass


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

    hardened_when = spec.get("hardened_when") or {}
    for vend, rx in hardened_when.items():
        try:
            re.compile(rx)
        except re.error as e:
            _fail(fid, f"hardened_when for {vend!r} does not compile: {e}")
        if vend not in detectors:
            _fail(fid, f"hardened_when for {vend!r} has no matching detector — without one there "
                       f"is no scope test, so every device would read as exposed")

    if mode == "proof":
        if not absent_when:
            _fail(fid, 'absence_means = "proof" requires an absent_when pattern — otherwise there '
                       'is nothing to prove absence with')
        missing = [v for v in detectors if v not in absent_when]
        if missing:
            _fail(fid, f'absence_means = "proof" but no absent_when for vendor(s) {missing}')

    fx = spec.get("fixtures") or {}
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
        for vend, rx in (spec.get("detectors") or {}).items():
            if vend in _NON_VENDOR_KEYS:
                _fail(fid, f"vendor name {vend!r} collides with a reserved key")
            flat[vend] = rx
        features[fid] = flat

    cve_rules = {str(k).strip().upper(): v for k, v in raw_cves.items()}
    _validate_cves(cve_rules, features)
    return features, cve_rules
