from __future__ import annotations

import os
import re
from pathlib import Path

from engines.cve.features import canonicalize
from engines.cve.rule_loader import load_rules

EXPOSED = "EXPOSED"
MITIGATED = "MITIGATED"
NEEDS_REVIEW = "NEEDS_REVIEW"
INDETERMINATE = "INDETERMINATE"

_FEATURES, _CVE_RULES = load_rules(Path(os.environ.get("DATA_DIR") or "data") / "rules" / "detectors.toml")


def has_rule(cve_id: str) -> bool:
    return (cve_id or "").strip().upper() in _CVE_RULES


def _detect(feature_id: str, cfg: str, vendor: str):
    feat = _FEATURES.get(feature_id)
    if not feat:
        return None, "", ""
    pat = feat.get(vendor) or feat.get("default")
    if not pat:
        return None, "", ""
    m = re.search(pat, cfg)
    return (True, m.group(0).strip(), pat) if m else (False, "", pat)


def ground(cve_id: str, running_config: str, vendor: str, platform: str = "") -> dict:
    cid = (cve_id or "").strip().upper()
    vendor = (vendor or "").strip().lower()
    rule = _CVE_RULES.get(cid)

    if not rule:
        return {"status": NEEDS_REVIEW, "reason": "no deterministic exposure rule for this CVE", "evidence": []}
    if rule.get("undecidable"):
        return {"status": INDETERMINATE, "reason": rule["undecidable"], "evidence": []}
    if not running_config or len(running_config.strip()) < 20:
        return {"status": NEEDS_REVIEW, "reason": "running-config unavailable/empty — cannot ground", "evidence": []}

    features = rule.get("features", [])
    present_hits: list = []
    hardened_hits: list = []
    patterns: dict = {}
    undetectable: list = []
    for fid in features:
        present, snippet, pattern = _detect(fid, running_config, vendor)
        patterns[fid] = pattern
        if present is None:
            undetectable.append(fid)
        elif present:
            hw = (_FEATURES[fid].get("hardened_when") or {}).get(vendor)
            hm = re.search(hw, running_config) if hw else None
            if hm:
                hardened_hits.append((fid, hm.group(0).strip(), hw))
            else:
                present_hits.append((fid, snippet, hw or ""))

    if present_hits:
        return {
            "status": EXPOSED,
            "reason": "vulnerable feature present: " + ", ".join(f for f, _, _ in present_hits),
            "feature": present_hits[0][0],
            "evidence": [{
                "feature": fid,
                "label": _FEATURES[fid]["label"],
                "matched_config_snippet": snip,
                "detector_pattern": patterns.get(fid, ""),
                "vulnerable_commands": (_FEATURES[fid].get("vulnerable_commands") or {}).get(
                    vendor, (_FEATURES[fid].get("vulnerable_commands") or {}).get("default", [])),
                **({"missing_hardening_pattern": hw,
                    "note": "the subsystem is present and the vendor's protective setting is not"}
                   if hw else {}),
                "source": "config_grounding",
            } for fid, snip, hw in present_hits],
        }

    if undetectable:
        return {
            "status": NEEDS_REVIEW,
            "reason": "feature(s) not detectable from running-config for this vendor: " + ", ".join(undetectable),
            "evidence": [],
        }

    unproven: list = []
    _hardened_ids = {f for f, _, _ in hardened_hits}
    for fid in features:
        if fid in _hardened_ids:
            continue
        spec = _FEATURES[fid]
        mode = spec.get("absence_means", "detect")
        if mode == "clear":
            continue
        if mode == "proof":
            off_rx = (spec.get("absent_when") or {}).get(vendor)
            if off_rx and re.search(off_rx, running_config):
                continue
            unproven.append(f"{fid} (no explicit 'disabled' line; silence may just be the default)")
        else:
            unproven.append(f"{fid} (absence of this pattern does not prove the feature is off)")

    if unproven:
        return {
            "status": NEEDS_REVIEW,
            "reason": "vulnerable feature not found, but absence is not proof for: "
                      + "; ".join(unproven),
            "evidence": [{
                "feature": fid,
                "label": _FEATURES[fid]["label"],
                "matched_config_snippet": "",
                "detector_pattern": patterns.get(fid, ""),
                "note": "detector did not match, and this feature's absence_means forbids "
                        "concluding the device is safe from that alone",
                "source": "config_grounding",
            } for fid in features],
        }

    if hardened_hits:
        return {
            "status": MITIGATED,
            "reason": "vendor's protective configuration present for: "
                      + ", ".join(f for f, _, _ in hardened_hits),
            "evidence": [{
                "feature": fid,
                "label": _FEATURES[fid]["label"],
                "matched_config_snippet": snip,
                "detector_pattern": hw,
                "note": "the vendor's protective setting is configured, so the precondition for "
                        "this CVE is not met on this device",
                "source": "config_grounding:hardened",
            } for fid, snip, hw in hardened_hits],
        }

    return {
        "status": MITIGATED,
        "reason": "vulnerable feature absent: " + ", ".join(features),
        "evidence": [{
            "feature": fid,
            "label": _FEATURES[fid]["label"],
            "matched_config_snippet": "",
            "detector_pattern": patterns.get(fid, ""),
            "vulnerable_commands": (_FEATURES[fid].get("vulnerable_commands") or {}).get(
                vendor, (_FEATURES[fid].get("vulnerable_commands") or {}).get("default", [])),
            "note": "precondition feature not present in running config",
            "source": "config_grounding",
        } for fid in features],
    }
