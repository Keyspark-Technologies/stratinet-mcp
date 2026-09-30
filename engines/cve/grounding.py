"""Deterministic config-feature grounding (P2).

A CVE is exploitable only if a specific feature is CONFIGURED — the advisory's "exposure
precondition". We decide EXPOSED vs MITIGATED by testing that feature against the device's
running config DETERMINISTICALLY, never via an LLM guess (the fail-open LLM defaulting to
`exposed=True` — and inventing "remove VXLAN" on a box with no VXLAN — was the bug this fixes).

Three outcomes, fail-CLOSED:
  EXPOSED       — the vulnerable feature is present in the running config (with the matched snippet)
  MITIGATED     — every required feature is detectable AND absent (grounded-safe, with evidence)
  NEEDS_REVIEW  — no rule for this CVE, or config empty/unavailable, or a feature can't be read
                  from the running config for this vendor. We NEVER auto-claim mitigated on a
                  guess, and NEVER auto-remediate a NEEDS_REVIEW finding.

Rules are hand-written in app/rules/detectors.toml, keyed by CVE id, and reviewed in git. No LLM
takes part in the decision or in authoring the detectors.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from engines.cve.features import canonicalize
from engines.cve.rule_loader import load_rules

EXPOSED = "EXPOSED"
MITIGATED = "MITIGATED"
NEEDS_REVIEW = "NEEDS_REVIEW"
# Terminal verdict: exposure is inherently NOT determinable from the running-config (platform/
# hardware-dependent — e.g. software-forwarding-only, hardware-IPsec). Unlike NEEDS_REVIEW (transient:
# no rule yet / config unavailable), no config rule will ever resolve it — it needs a human decision
# (verify the platform condition, then upgrade). Fail-closed toward ACTION, never silently dropped.
INDETERMINATE = "INDETERMINATE"

# ── Rules ────────────────────────────────────────────────────────────────────
# Loaded from app/rules/detectors.toml. They used to be literals right here, which meant adding a
# detector was surgery on the module that decides every verdict; the data file makes it a data edit
# while keeping them in git, where each one has an author, a reviewer and a diff.
#
# Loading is strict and fatal: a rule file that fails validation stops the service rather than
# starting with detectors missing, because a detector that silently fails to load reads as "feature
# absent" -- the exact false-clean this module exists to prevent.
_FEATURES, _CVE_RULES = load_rules(Path(os.environ.get("DATA_DIR") or "data") / "rules" / "detectors.toml")


def has_rule(cve_id: str) -> bool:
    return (cve_id or "").strip().upper() in _CVE_RULES


def _detect(feature_id: str, cfg: str, vendor: str):
    """Return (present, snippet, pattern).

    present is True/False, or None if there is no detector for this feature+vendor (=> the feature
    is not readable from config here). `pattern` is the regex actually applied, and it is returned
    even on a miss: an ABSENCE verdict is only auditable if the reader can see what was searched
    for. Without it, "vulnerable feature absent" is an assertion no reviewer can falsify -- which
    is how a rule that greps for a bare `fgfm` string, on a platform where FGFM is enabled by
    default and gated by an interface's allowaccess list, looked indistinguishable from a correct
    one.
    """
    feat = _FEATURES.get(feature_id)
    if not feat:
        return None, "", ""
    pat = feat.get(vendor) or feat.get("default")
    if not pat:
        return None, "", ""
    m = re.search(pat, cfg)
    return (True, m.group(0).strip(), pat) if m else (False, "", pat)


def ground(cve_id: str, running_config: str, vendor: str, platform: str = "") -> dict:
    """Deterministically decide a CVE's exposure on one device.

    Uses the hand-written rule from detectors.toml if one covers this CVE; otherwise NEEDS_REVIEW.
    Returns {status, reason, feature, evidence:[...]}. status ∈ EXPOSED|MITIGATED|NEEDS_REVIEW.

    There is no second, generated source of rules any more. LLM rule generation produced 203
    detectors against 12 hand-written ones and decided 22 findings against their 116 -- roughly a
    ninetieth of the return per artifact -- while contributing every brittle rule, both trust gates
    and the approval queue built to police them. It could also only ever EXPOSE, never clear, after
    the safety fix, so the queue approved things that could no longer do the thing approval was for.
    Rules are hand-written, reviewed in git, and tested against real configs."""
    cid = (cve_id or "").strip().upper()
    vendor = (vendor or "").strip().lower()
    rule = _CVE_RULES.get(cid)

    if not rule:
        return {"status": NEEDS_REVIEW, "reason": "no deterministic exposure rule for this CVE", "evidence": []}
    if rule.get("undecidable"):
        # Exposure is inherently NOT determinable from config (platform/hardware-dependent) → terminal
        # INDETERMINATE (manual assessment), not a transient NEEDS_REVIEW.
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
            # Present is not automatically exposed. For an advisory of the form "vulnerable UNLESS
            # you configured Y", the detector establishes only that the subsystem exists here;
            # hardened_when is the vendor's protective setting, and finding it is POSITIVE evidence
            # that the precondition is not met -- a much stronger claim than any absence argument,
            # which is why it clears regardless of absence_means.
            hw = (_FEATURES[fid].get("hardened_when") or {}).get(vendor)
            hm = re.search(hw, running_config) if hw else None
            if hm:
                hardened_hits.append((fid, hm.group(0).strip(), hw))
            else:
                # Carry the hardening pattern we looked for and did NOT find. For a
                # vulnerable-unless-hardened rule the verdict rests on two facts, and recording
                # only the first made the evidence read as a non-sequitur: CVE-2024-7095 showed
                # "SNMP without a transmit max-size limit" over a matched line of
                # `snmp-server community`, which is not that -- it is only the scope half. The
                # missing protective line is the other half and is what the remediation restores.
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
                # The regex that matched. An operator can re-run it against the device and get the
                # same line, which is what makes the verdict checkable rather than asserted.
                "detector_pattern": patterns.get(fid, ""),
                "vulnerable_commands": (_FEATURES[fid].get("vulnerable_commands") or {}).get(
                    vendor, (_FEATURES[fid].get("vulnerable_commands") or {}).get("default", [])),
                # Only set for a vulnerable-unless-hardened rule: the protective configuration the
                # vendor asks for, which is absent here. Without it the matched line alone does not
                # explain the verdict.
                **({"missing_hardening_pattern": hw,
                    "note": "the subsystem is present and the vendor's protective setting is not"}
                   if hw else {}),
                "source": "config_grounding",
            } for fid, snip, hw in present_hits],
        }

    # Nothing present. If any required feature isn't detectable here, we can't prove absence.
    if undetectable:
        return {
            "status": NEEDS_REVIEW,
            "reason": "feature(s) not detectable from running-config for this vendor: " + ", ".join(undetectable),
            "evidence": [],
        }

    # Absent is not automatically safe. How much a NON-match proves depends on the feature, and
    # each rule states it (absence_means):
    #   clear  the feature must appear in the running config to be active, so absence is absence
    #   detect a non-match proves nothing -- e.g. the feature can be on by default with no line
    #   proof  only an explicit "it is off" line clears it. FortiOS `show` omits settings at their
    #          default, so a config that simply never mentions the setting is ambiguous, not safe.
    unproven: list = []
    _hardened_ids = {f for f, _, _ in hardened_hits}
    for fid in features:
        # A feature we found the vendor's protective line for needs no absence argument -- we have
        # the positive evidence instead.
        if fid in _hardened_ids:
            continue
        spec = _FEATURES[fid]
        mode = spec.get("absence_means", "detect")
        if mode == "clear":
            continue
        if mode == "proof":
            off_rx = (spec.get("absent_when") or {}).get(vendor)
            if off_rx and re.search(off_rx, running_config):
                continue        # the config says outright that it is disabled
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

    # Every feature is either absent (and its rule permits that to clear) or present-but-hardened.
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
            # THE point of this change. A MITIGATED verdict says the device is safe without
            # patching; the only thing backing it is that this pattern found nothing. Recording it
            # lets a reviewer judge whether the search was the right one -- absence of a config
            # line is not absence of a feature when the feature is on by default.
            "detector_pattern": patterns.get(fid, ""),
            "vulnerable_commands": (_FEATURES[fid].get("vulnerable_commands") or {}).get(
                vendor, (_FEATURES[fid].get("vulnerable_commands") or {}).get("default", [])),
            "note": "precondition feature not present in running config",
            "source": "config_grounding",
        } for fid in features],
    }
