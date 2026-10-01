from __future__ import annotations

from dataclasses import dataclass

from common.validate import ToolInputError

NOT_AFFECTED = "not_affected"
VULNERABLE = "vulnerable"
DEPENDS_ON_CONFIGURATION = "depends_on_configuration"
LIKELY_VULNERABLE_UNLESS_DISABLED = "likely_vulnerable_unless_disabled"
AFFECTED_VERSION_CONFIGURATION_NOT_ASSESSED = "affected_version_configuration_not_assessed"
CANNOT_DETERMINE = "cannot_determine"

VERDICTS = (
    NOT_AFFECTED,
    VULNERABLE,
    DEPENDS_ON_CONFIGURATION,
    LIKELY_VULNERABLE_UNLESS_DISABLED,
    AFFECTED_VERSION_CONFIGURATION_NOT_ASSESSED,
    CANNOT_DETERMINE,
)

VERSION_UNPARSEABLE = "version_unparseable"
VERSION_LINES_NOT_COMPARABLE = "version_lines_not_comparable"
AFFECTED_RANGE_UNREADABLE = "affected_range_unreadable"
NO_ADVISORY_DATA = "no_advisory_data"
PLATFORM_DEPENDENT = "platform_dependent"
FEATURE_NOT_READABLE_FOR_VENDOR = "feature_not_readable_for_vendor"

VERSION_REASONS = (VERSION_UNPARSEABLE, VERSION_LINES_NOT_COMPARABLE, AFFECTED_RANGE_UNREADABLE)

REASONS = (
    VERSION_UNPARSEABLE,
    VERSION_LINES_NOT_COMPARABLE,
    AFFECTED_RANGE_UNREADABLE,
    NO_ADVISORY_DATA,
    PLATFORM_DEPENDENT,
    FEATURE_NOT_READABLE_FOR_VENDOR,
)

EXPOSED = "EXPOSED"
MITIGATED = "MITIGATED"
NEEDS_REVIEW = "NEEDS_REVIEW"
INDETERMINATE = "INDETERMINATE"

GROUNDING = (EXPOSED, MITIGATED, NEEDS_REVIEW, INDETERMINATE)

PROOF_VERSION = "version"
PROOF_CONFIG = "config"

READABLE_ALL = "all"
READABLE_SOME = "some"
READABLE_NONE = "none"

READABILITY = (READABLE_ALL, READABLE_SOME, READABLE_NONE)

FACT_PRESENT = "present"
FACT_ABSENT = "absent"
FACT_EXPLICITLY_DISABLED = "explicitly_disabled"
FACT_HARDENED = "hardened"

FACT_VALUES = (FACT_PRESENT, FACT_ABSENT, FACT_EXPLICITLY_DISABLED, FACT_HARDENED)

DETECTOR_VENDOR = {"arista_eos": "arista", "fortinet_fortios": "fortinet"}


@dataclass(frozen=True)
class Facts:
    has_rows: bool
    version_match: bool | None
    version_reason: str | None = None
    has_rule: bool = False
    undecidable: bool = False
    readable: str = READABLE_ALL
    config_supplied: bool = False
    default_on: bool = False
    grounding: str | None = None
    feature_unreadable: bool = False


@dataclass(frozen=True)
class Verdict:
    verdict: str
    reason: str | None = None
    proof: str | None = None


@dataclass(frozen=True)
class RuleFacts:
    has_rule: bool
    undecidable: bool
    readable: str
    default_on: bool
    features: tuple[str, ...]


def _detector(feature: dict, detector_key: str):
    return feature.get(detector_key) or feature.get("default")


def rule_facts(cve_id: str, vendor: str, features: dict, cve_rules: dict) -> RuleFacts:
    rule = cve_rules.get((cve_id or "").strip().upper())
    if not rule:
        return RuleFacts(False, False, READABLE_ALL, False, ())
    if rule.get("undecidable"):
        return RuleFacts(True, True, READABLE_ALL, False, ())
    detector_key = DETECTOR_VENDOR[vendor]
    ids = tuple(rule.get("features") or ())
    readable = [bool(_detector(features.get(f) or {}, detector_key)) for f in ids]
    if all(readable):
        level = READABLE_ALL
    elif any(readable):
        level = READABLE_SOME
    else:
        level = READABLE_NONE
    default_on = any(_cited_default_on(features.get(f) or {}, detector_key) for f in ids)
    return RuleFacts(True, False, level, default_on, ids)


def _cited_default_on(feature: dict, detector_key: str) -> bool:
    entry = (feature.get("default_on") or {}).get(detector_key)
    if not isinstance(entry, dict):
        return False
    return bool(entry.get("enabled")) and bool(entry.get("quote")) and bool(entry.get("url"))


def _invalid_fact() -> ToolInputError:
    return ToolInputError("invalid_feature_fact", field="feature_facts")


def check_feature_facts(feature_facts, vendor: str, features: dict) -> None:
    if not isinstance(feature_facts, dict):
        raise _invalid_fact()
    detector_key = DETECTOR_VENDOR[vendor]
    for fid, value in feature_facts.items():
        spec = features.get(fid) if isinstance(fid, str) else None
        if spec is None or value not in FACT_VALUES:
            raise _invalid_fact()
        if not _detector(spec, detector_key):
            raise _invalid_fact()
        if value == FACT_EXPLICITLY_DISABLED and not (spec.get("absent_when") or {}).get(
            detector_key
        ):
            raise _invalid_fact()
        if value == FACT_HARDENED and not (spec.get("hardened_when") or {}).get(detector_key):
            raise _invalid_fact()


def ground_facts(
    cve_id: str, vendor: str, feature_facts: dict, features: dict, cve_rules: dict
) -> str:
    check_feature_facts(feature_facts, vendor, features)
    rule = cve_rules.get((cve_id or "").strip().upper())
    if not rule:
        return NEEDS_REVIEW
    if rule.get("undecidable"):
        return INDETERMINATE
    detector_key = DETECTOR_VENDOR[vendor]
    ids = rule.get("features") or []
    present, hardened, undetectable = [], set(), []
    for fid in ids:
        if not _detector(features.get(fid) or {}, detector_key):
            undetectable.append(fid)
            continue
        fact = feature_facts.get(fid)
        if fact == FACT_PRESENT:
            present.append(fid)
        elif fact == FACT_HARDENED:
            hardened.add(fid)
    if present:
        return EXPOSED
    if undetectable:
        return NEEDS_REVIEW
    for fid in ids:
        if fid in hardened:
            continue
        fact = feature_facts.get(fid)
        mode = (features.get(fid) or {}).get("absence_means", "detect")
        if mode == "clear" and fact in (FACT_ABSENT, FACT_EXPLICITLY_DISABLED):
            continue
        if mode == "proof" and fact == FACT_EXPLICITLY_DISABLED:
            continue
        return NEEDS_REVIEW
    return MITIGATED


def derive(facts: Facts) -> Verdict:
    if not facts.has_rows:
        return Verdict(CANNOT_DETERMINE, NO_ADVISORY_DATA)
    if facts.version_match is False:
        return Verdict(NOT_AFFECTED, proof=PROOF_VERSION)
    if facts.version_match is None:
        if facts.version_reason not in VERSION_REASONS:
            raise ValueError("version_match is None without a version reason")
        return Verdict(CANNOT_DETERMINE, facts.version_reason)
    if not facts.has_rule:
        return Verdict(AFFECTED_VERSION_CONFIGURATION_NOT_ASSESSED)
    if facts.undecidable:
        return Verdict(CANNOT_DETERMINE, PLATFORM_DEPENDENT)
    if facts.readable not in READABILITY:
        raise ValueError("unknown readability")
    if facts.readable == READABLE_NONE:
        return Verdict(CANNOT_DETERMINE, FEATURE_NOT_READABLE_FOR_VENDOR)
    if not facts.config_supplied:
        return _unproven(facts)
    if facts.grounding not in GROUNDING:
        raise ValueError("config supplied without a grounding status")
    if facts.grounding == EXPOSED:
        return Verdict(VULNERABLE)
    if facts.grounding == MITIGATED:
        return Verdict(NOT_AFFECTED, proof=PROOF_CONFIG)
    if facts.grounding == INDETERMINATE:
        return Verdict(CANNOT_DETERMINE, PLATFORM_DEPENDENT)
    if facts.feature_unreadable:
        return Verdict(CANNOT_DETERMINE, FEATURE_NOT_READABLE_FOR_VENDOR)
    return _unproven(facts)


def _unproven(facts: Facts) -> Verdict:
    if facts.default_on:
        return Verdict(LIKELY_VULNERABLE_UNLESS_DISABLED)
    return Verdict(DEPENDS_ON_CONFIGURATION)


def facts_for(lookup, cve_id: str, rules: RuleFacts, grounding: str | None = None) -> Facts:
    cid = (cve_id or "").strip().upper()
    if not lookup.version_comparable:
        version_match, version_reason = None, VERSION_UNPARSEABLE
    else:
        hits = [a for a in lookup.advisories if a.cve_id == cid]
        if not hits:
            version_match, version_reason = False, None
        elif any(a.substantiated for a in hits):
            version_match, version_reason = True, None
        elif any(a.version_undecidable for a in hits):
            version_match, version_reason = None, VERSION_LINES_NOT_COMPARABLE
        else:
            version_match, version_reason = None, AFFECTED_RANGE_UNREADABLE
    return Facts(
        has_rows=cid in lookup.cves_seen,
        version_match=version_match,
        version_reason=version_reason,
        has_rule=rules.has_rule,
        undecidable=rules.undecidable,
        readable=rules.readable,
        config_supplied=grounding is not None,
        default_on=rules.default_on,
        grounding=grounding,
        feature_unreadable=grounding == NEEDS_REVIEW and rules.readable == READABLE_SOME,
    )
