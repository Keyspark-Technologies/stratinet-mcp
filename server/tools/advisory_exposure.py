import copy
import datetime
import re
from functools import lru_cache
from typing import Any

from common.project import fit, project, response_size
from common.validate import ToolInputError, check_enum, check_fields, check_size
from engines.cve import corpus_query
from engines.cve import public_verdict as pv
from engines.cve.applicability import (
    CLEARED_NOT_THIS_PRODUCT,
    CLEARED_UNCOVERED,
    CLEARED_VENDOR,
    CLEARED_VERSION,
    SUPPORTED_VENDORS,
    advisories_for_version,
)
from engines.cve.rule_loader import load_rules
from engines.cve.version_match import _num, matches_any_range, parse_version
from server.data import data_dir, data_version

NAME = "advisory_exposure"

BASIS = "deterministic — version-range comparison and hand-written config detectors; no model"

DESCRIPTION = (
    "Says whether an Arista EOS or Fortinet FortiOS software version is exposed to a vendor "
    "security advisory. Give vendor and version; add cve_id for one CVE, or omit it to list every "
    "CVE that applies to that version. Optionally add running_config or feature_facts to settle "
    "whether the vulnerable feature is in use. Answers are deterministic and never guess "
    "'not affected': when unsure the answer says what would settle it."
)

MAX_CONFIG_BYTES = 256 * 1024
MAX_HARDWARE_MODEL_BYTES = 128
MAX_VERSION_BYTES = 64
MAX_CVE_ID_BYTES = 64
MAX_SINGLE_BYTES = 8 * 1024
MAX_LIST_BYTES = 64 * 1024
MAX_FINDINGS = 25
MAX_EVIDENCE = 5
MAX_SNIPPET = 240
MAX_COMMANDS = 8
MAX_RANGES = 16

CLEARED_BY_RANGE = "affected_range"
CLEARED_BY_VENDOR = "vendor_statement"

CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$")

CONFIG_LISTING = {
    "arista_eos": "show running-config",
    "fortinet_fortios": "show full-configuration",
}

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

NO_RULE_REASON = "no deterministic exposure rule exists for this CVE"

SCHEMA = {
    "type": "object",
    "properties": {
        "vendor": {"type": "string", "enum": list(SUPPORTED_VENDORS)},
        "version": {"type": "string"},
        "cve_id": {"type": "string"},
        "hardware_model": {"type": "string"},
        "running_config": {"type": "string"},
        "feature_facts": {
            "type": "object",
            "additionalProperties": {"type": "string", "enum": list(pv.FACT_VALUES)},
        },
    },
    "required": ["vendor", "version"],
    "additionalProperties": False,
}

EXAMPLES = {
    NAME: [
        {"vendor": "fortinet_fortios", "version": "7.0.3", "cve_id": "CVE-2024-21762"},
        {"vendor": "arista_eos", "version": "4.28.1F"},
        {
            "vendor": "fortinet_fortios",
            "version": "7.0.3",
            "cve_id": "CVE-2024-21762",
            "feature_facts": {"ssl_vpn": "explicitly_disabled"},
        },
    ]
}

ENVELOPE = (
    "verdict",
    "cve_id",
    "vendor",
    "version",
    "advisory",
    "reason",
    "detail",
    "feature",
    "feature_label",
    "default_state",
    "default_on_source",
    "evidence",
    "vulnerable_commands",
    "check_commands",
    "check_source",
    "decides",
    "conditions",
    "hardening_commands",
    "fixed_in",
    "ranges_checked",
    "cleared_by",
    "no_rule_reason",
    "what_would_settle_it",
    "basis",
    "assessed",
    "data_version",
    "limits",
)

HOISTED = ("vendor", "version", "basis", "data_version")

SINGLE_SHED = (
    ("hardening_commands", 0),
    ("conditions", 0),
    ("check_commands", 1),
    ("vulnerable_commands", 1),
    ("ranges_checked", 1),
)

EVIDENCE_FIELDS = (
    "feature",
    "label",
    "matched_config_snippet",
    "detector_pattern",
    "vulnerable_commands",
    "note",
)


@lru_cache(maxsize=1)
def _rules() -> tuple[dict, dict]:
    return load_rules(data_dir() / "rules" / "detectors.toml")


def _string(arguments: dict, name: str) -> str | None:
    value = arguments.get(name)
    if value is not None and not isinstance(value, str):
        raise ToolInputError("invalid_value", field=name)
    return value


def _read_input(arguments: dict) -> dict:
    check_fields(
        arguments,
        required=("vendor", "version"),
        optional=("cve_id", "hardware_model", "running_config", "feature_facts"),
    )
    vendor = check_enum(arguments["vendor"], SUPPORTED_VENDORS, "vendor")
    version = check_size(_string(arguments, "version"), MAX_VERSION_BYTES, "version")
    if version is None:
        raise ToolInputError("invalid_value", field="version")
    cve_id = check_size(_string(arguments, "cve_id"), MAX_CVE_ID_BYTES, "cve_id")
    if cve_id is not None:
        cve_id = cve_id.strip().upper()
        if not CVE_ID.match(cve_id):
            raise ToolInputError("malformed_cve_id", field="cve_id")
    check_size(_string(arguments, "hardware_model"), MAX_HARDWARE_MODEL_BYTES, "hardware_model")
    config = check_size(_string(arguments, "running_config"), MAX_CONFIG_BYTES, "running_config")
    facts = arguments.get("feature_facts")
    if facts is not None:
        features, _ = _rules()
        pv.check_feature_facts(facts, vendor, features)
    return {
        "vendor": vendor,
        "version": version,
        "cve_id": cve_id,
        "running_config": config,
        "feature_facts": facts,
    }


def _published(text: str) -> str | None:
    for fmt in ("%b %d, %Y", "%B %d, %Y", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime((text or "").strip(), fmt).date().isoformat()
        except ValueError:
            continue
    return None


def _advisory(match) -> dict | None:
    if match is None:
        return None
    return {
        "id": match.advisory_id,
        "url": match.url or None,
        "published": _published(match.published),
        "severity": (match.severity or "").lower() or None,
    }


def _fixed_in(fixes: list, version: str) -> str | None:
    pv_ = parse_version(version)
    if pv_ is None:
        return None
    train = _num(pv_)[:2]
    same = []
    for fix in fixes:
        pf = parse_version(fix)
        if pf is not None and _num(pf)[:2] == train:
            same.append((_num(pf), fix))
    return min(same)[1] if same else None


def _train(text: str) -> tuple:
    parsed = parse_version(text or "")
    return _num(parsed)[:2] if parsed is not None else ()


def _own_train(r: dict, train: tuple) -> bool:
    return bool(train) and any(_train(r.get(k)) == train for k in ("train", "introduced", "fixed"))


def _ranges(ranges: list, version: str) -> list:
    out = []
    for r in ranges:
        row = {
            "introduced": r.get("introduced", "") or "",
            "fixed": r.get("fixed", "") or "",
            "fixed_inclusive": bool(r.get("fixed_inclusive", False)),
        }
        if r.get("train"):
            row["train"] = r["train"]
        if row not in out:
            out.append(row)
    train = _train(version)
    return sorted(out, key=lambda r: not _own_train(r, train))


def _covering(ranges: list, version: str) -> list:
    return [r for r in ranges if matches_any_range(version, [r]) is True]


def _proving(lookup, cve_id: str, version: str) -> tuple[str | None, list]:
    kept = [a for a in lookup.advisories if a.cve_id == cve_id]
    if kept:
        return None, kept
    cleared = [a for a in lookup.cleared if a.cve_id == cve_id]
    by_version = [a for a in cleared if a.cleared == CLEARED_VERSION]
    if by_version:
        return CLEARED_VERSION, by_version
    by_vendor = [a for a in cleared if a.cleared == CLEARED_VENDOR]
    if by_vendor:
        by_vendor.sort(key=lambda a: not _covering(a.ranges_checked, version))
        return CLEARED_VENDOR, by_vendor
    return CLEARED_UNCOVERED, [a for a in cleared if a.cleared == CLEARED_UNCOVERED]


def _sibling_fix(lookup, cve_id: str, version: str) -> str | None:
    current = parse_version(version)
    if current is None:
        return None
    siblings = [
        a
        for a in lookup.cleared
        if a.cve_id == cve_id and a.cleared not in (CLEARED_NOT_THIS_PRODUCT, CLEARED_UNCOVERED)
    ]
    fixes = {f for a in siblings for f in a.fixed_versions}
    later = sorted(
        f for f in fixes if (p := parse_version(f)) is not None and _num(p) > _num(current)
    )
    return _fixed_in(later, version)


def _detector_key(vendor: str) -> str:
    return pv.DETECTOR_VENDOR[vendor]


def _vulnerable_commands(spec: dict, key: str) -> list:
    commands = spec.get("vulnerable_commands") or {}
    return list(commands.get(key, commands.get("default", [])))


def _decides(spec: dict, key: str) -> dict:
    if not (spec.get(key) or spec.get("default")):
        return {"if_present": pv.VULNERABLE}
    out = {"if_present": pv.VULNERABLE}
    hardened = bool((spec.get("hardened_when") or {}).get(key))
    mode = spec.get("absence_means", "detect")
    if hardened:
        out["if_hardened"] = pv.NOT_AFFECTED
    if mode == "clear":
        out["if_absent"] = pv.NOT_AFFECTED
    elif mode == "proof" and (spec.get("absent_when") or {}).get(key):
        out["if_explicitly_disabled"] = pv.NOT_AFFECTED
    return out


def _commands(rows: list) -> list:
    out = []
    for row in rows:
        for command in (row.get("commands") or "").split(" ;; "):
            command = command.strip()
            if command and command not in out:
                out.append(command)
    return out


def _union(lists) -> list:
    out = []
    for items in lists:
        for item in items:
            if item not in out:
                out.append(item)
    return out


def _actions(advisory_ids: list) -> dict:
    by_advisory: dict = {}
    for row in corpus_query.actions_for(advisory_ids):
        by_advisory.setdefault(row["advisory_id"], {}).setdefault(row["kind"], []).append(row)
    return by_advisory


def _grounding(cve_id: str, vendor: str, inputs: dict) -> tuple[str | None, list]:
    features, cve_rules = _rules()
    facts = inputs["feature_facts"]
    if facts is not None:
        status = pv.ground_facts(cve_id, vendor, facts, features, cve_rules)
        return status, _facts_evidence(cve_id, vendor, facts, status, features, cve_rules)
    config = inputs["running_config"]
    if config is None:
        return None, []
    from engines.cve.grounding import ground

    result = ground(cve_id, config, _detector_key(vendor))
    evidence = []
    for row in result.get("evidence") or []:
        item = project(row, EVIDENCE_FIELDS)
        item["matched_config_snippet"] = (item.get("matched_config_snippet") or "")[:MAX_SNIPPET]
        evidence.append(item)
    return result["status"], evidence


def _facts_evidence(cve_id, vendor, facts, status, features, cve_rules) -> list:
    rule = cve_rules.get(cve_id) or {}
    key = _detector_key(vendor)
    evidence = []
    for fid in rule.get("features") or []:
        spec = features.get(fid) or {}
        value = facts.get(fid)
        if status == pv.EXPOSED and value != pv.FACT_PRESENT:
            continue
        evidence.append(
            {
                "feature": fid,
                "label": spec.get("label", fid),
                "matched_config_snippet": "",
                "detector_pattern": spec.get(key) or spec.get("default") or "",
                "vulnerable_commands": _vulnerable_commands(spec, key),
                "note": f"feature_facts reports {value}"
                if value
                else "not reported in feature_facts",
            }
        )
    return evidence


def _settle(reason: str, advisory: dict | None, fixed_in: str | None, detail: str | None) -> list:
    url = (advisory or {}).get("url")
    if reason == pv.VERSION_UNPARSEABLE:
        return ["give the full release version, for example 7.0.3 or 4.28.1F"]
    if reason == pv.VERSION_LINES_NOT_COMPARABLE:
        if fixed_in:
            return [f"confirm whether this release contains the fix for its train: {fixed_in}"]
        return [f"check the advisory's affected-versions table for this release train: {url}"]
    if reason == pv.AFFECTED_RANGE_UNREADABLE:
        out = [f"check the advisory's affected-versions table: {url}"]
        if fixed_in:
            out.append(f"fixed in {fixed_in}")
        return out
    if reason == pv.NO_ADVISORY_DATA:
        return ["check the vendor's advisory for this CVE; no advisory data for this product"]
    if reason == pv.PLATFORM_DEPENDENT:
        return [f"confirm the platform condition: {detail}" if detail else "confirm the platform"]
    return ["check the vendor advisory: this feature cannot be read from configuration here"]


def _cap(out: dict, name: str, limit: int) -> None:
    items = out.get(name)
    if isinstance(items, list) and len(items) > limit:
        out[name] = items[:limit]
        out.setdefault("limits", {})["response_truncated"] = True


def _bound(out: dict) -> dict:
    _cap(out, "evidence", MAX_EVIDENCE)
    for row in out.get("evidence") or []:
        _cap(row, "vulnerable_commands", MAX_COMMANDS)
        if row.pop("limits", None):
            out.setdefault("limits", {})["response_truncated"] = True
    for name in ("vulnerable_commands", "check_commands", "hardening_commands"):
        _cap(out, name, MAX_COMMANDS)
    _cap(out, "ranges_checked", MAX_RANGES)
    return out


def _finding(lookup, cve_id: str, inputs: dict, actions: dict | None) -> dict:
    return _bound(_derive(lookup, cve_id, inputs, actions))


def _derive(lookup, cve_id: str, inputs: dict, actions: dict | None) -> dict:
    vendor, version = inputs["vendor"], lookup.version
    features, cve_rules = _rules()
    rules = pv.rule_facts(cve_id, vendor, features, cve_rules)
    status, evidence = _grounding(cve_id, vendor, inputs)
    facts = pv.facts_for(lookup, cve_id, rules, status)
    verdict = pv.derive(facts)
    kind, proving = _proving(lookup, cve_id, version)
    match = (proving or [None])[0]
    fixes = sorted({f for a in proving for f in a.fixed_versions})
    fixed_in = _fixed_in(fixes, version)
    if fixed_in is None and kind is None:
        fixed_in = _sibling_fix(lookup, cve_id, version)
    advisory = _advisory(match) if facts.has_rows else None
    out: dict[str, Any] = {
        "verdict": verdict.verdict,
        "cve_id": cve_id,
        "vendor": vendor,
        "version": version,
        "advisory": advisory,
        "assessed": {
            "version_compared": facts.has_rows and facts.version_match is not None,
            "configuration_assessed": verdict.verdict == pv.VULNERABLE
            or verdict.proof == pv.PROOF_CONFIG,
        },
    }
    rule = cve_rules.get(cve_id) or {}
    key = _detector_key(vendor)
    rule_features = list(rule.get("features") or [])
    if verdict.verdict == pv.CANNOT_DETERMINE:
        detail = rule.get("undecidable") if verdict.reason == pv.PLATFORM_DEPENDENT else None
        out["reason"] = verdict.reason
        if detail:
            out["detail"] = detail
        out["what_would_settle_it"] = _settle(verdict.reason, advisory, fixed_in, detail)
        return out
    if verdict.verdict == pv.NOT_AFFECTED:
        if verdict.proof == pv.PROOF_VERSION and kind == CLEARED_VENDOR:
            spans = [r for a in proving for r in _covering(a.ranges_checked, version)]
            out["reason"] = (
                f"the vendor's advisory states version {version} is not affected"
                if spans
                else "the vendor's advisory states this product is not affected"
            )
            out["cleared_by"] = CLEARED_BY_VENDOR
            out["fixed_in"] = fixed_in
            out["ranges_checked"] = _ranges(spans, version)
            out["assessed"]["version_compared"] = bool(spans)
        elif verdict.proof == pv.PROOF_VERSION:
            out["reason"] = f"version {version} is outside every affected range for this product"
            out["cleared_by"] = CLEARED_BY_RANGE
            out["fixed_in"] = fixed_in
            out["ranges_checked"] = _ranges([r for a in proving for r in a.ranges_checked], version)
        else:
            out["reason"] = "the vulnerable feature is not in use on this device"
            out["evidence"] = evidence
            out["fixed_in"] = fixed_in
        return out
    if verdict.verdict == pv.AFFECTED_VERSION_CONFIGURATION_NOT_ASSESSED:
        out["reason"] = f"version {version} is within the affected range; {NO_RULE_REASON}"
        out["no_rule_reason"] = NO_RULE_REASON
        out["fixed_in"] = fixed_in
        out["ranges_checked"] = _ranges([r for a in proving for r in a.affected_ranges], version)
        return out
    first = rule_features[0] if rule_features else None
    cited = None
    if verdict.verdict == pv.LIKELY_VULNERABLE_UNLESS_DISABLED:
        cited = pv.default_on_source(rule_features, key, features)
        if cited is None:
            raise ValueError("likely_vulnerable_unless_disabled without a cited default_on")
        first = cited[0]
    if verdict.verdict == pv.VULNERABLE:
        present = {e["feature"] for e in evidence}
        matched = [f for f in rule_features if f in present] or rule_features[:1]
        out["feature"] = matched[0] if matched else None
        out["reason"] = "vulnerable feature present: " + ", ".join(e["feature"] for e in evidence)
        out["evidence"] = evidence
        out["vulnerable_commands"] = _union(
            _vulnerable_commands(features.get(f) or {}, key) for f in matched
        )
        out["fixed_in"] = fixed_in
        return out
    spec = features.get(first) or {}
    out["feature"] = first
    out["feature_label"] = spec.get("label", first)
    out["vulnerable_commands"] = _union(
        _vulnerable_commands(features.get(f) or {}, key) for f in rule_features
    )
    rows = (actions or {}).get(match.advisory_id if match else "", {})
    check = _commands(rows.get("verify", []))
    out["check_commands"] = check or [CONFIG_LISTING[vendor]]
    out["check_source"] = "advisory" if check else "config_listing"
    out["decides"] = _decides(spec, key)
    if len(rule_features) > 1:
        out["conditions"] = [
            {
                "feature": f,
                "feature_label": (features.get(f) or {}).get("label", f),
                "decides": _decides(features.get(f) or {}, key),
            }
            for f in rule_features
        ]
    out["fixed_in"] = fixed_in
    if verdict.verdict == pv.LIKELY_VULNERABLE_UNLESS_DISABLED:
        out["reason"] = (
            "the affected feature is enabled by default; exposure ends only if it is disabled"
        )
        out["default_state"] = "enabled"
        out["default_on_source"] = cited[1]
        hardening = _commands(rows.get("workaround", []))
        if hardening:
            out["hardening_commands"] = hardening
        return out
    out["reason"] = (
        f"version {version} is in the affected range; exposure depends on the configuration: "
        f"{out['feature_label']}"
    )
    return out


def _needs_actions(finding: dict) -> bool:
    return finding["verdict"] in (
        pv.DEPENDS_ON_CONFIGURATION,
        pv.LIKELY_VULNERABLE_UNLESS_DISABLED,
    )


def _single(inputs: dict) -> dict:
    lookup = advisories_for_version(inputs["vendor"], inputs["version"])
    cve_id = inputs["cve_id"]
    finding = _finding(lookup, cve_id, inputs, None)
    if _needs_actions(finding) and finding["advisory"]:
        finding = _finding(lookup, cve_id, inputs, _actions([finding["advisory"]["id"]]))
    finding["basis"] = BASIS
    finding["data_version"] = data_version(corpus=True)
    payload = project(finding, ENVELOPE)
    truncated = bool(payload.pop("limits", {}).get("response_truncated"))
    out = copy.deepcopy(payload)
    out["limits"] = {"response_truncated": False}
    for name, keep in SINGLE_SHED:
        items = out.get(name)
        if not isinstance(items, list):
            continue
        while len(items) > keep and response_size(out) > MAX_SINGLE_BYTES:
            items.pop()
            truncated = True
    fitted = fit(out, MAX_SINGLE_BYTES, ())
    if truncated:
        fitted["limits"]["response_truncated"] = True
    return fitted


def _sort_key(finding: dict) -> tuple:
    severity = ((finding.get("advisory") or {}).get("severity") or "").lower()
    return (SEVERITY_RANK.get(severity, len(SEVERITY_RANK)), finding["cve_id"])


def _list(inputs: dict) -> dict:
    lookup = advisories_for_version(inputs["vendor"], inputs["version"])
    if not lookup.version_comparable:
        raise ToolInputError("version_unparseable", field="version")
    findings = []
    for cve_id in lookup.cves_seen:
        finding = _finding(lookup, cve_id, inputs, None)
        if finding["verdict"] == pv.NOT_AFFECTED and "ranges_checked" in finding:
            continue
        if finding.get("reason") == pv.NO_ADVISORY_DATA:
            continue
        findings.append(finding)
    findings.sort(key=_sort_key)
    total = len(findings)
    returned = findings[:MAX_FINDINGS]
    ids = sorted({f["advisory"]["id"] for f in returned if _needs_actions(f) and f["advisory"]})
    if ids:
        actions = _actions(ids)
        returned = [
            _finding(lookup, f["cve_id"], inputs, actions) if _needs_actions(f) else f
            for f in returned
        ]
    capped = any((f.get("limits") or {}).get("response_truncated") for f in returned)
    fields = tuple(n for n in ENVELOPE if n not in HOISTED and n != "limits")
    rows = [project(f, fields) for f in returned]
    payload = {
        "mode": "list",
        "vendor": inputs["vendor"],
        "version": lookup.version,
        "checked": len(lookup.cves_seen),
        "total": total,
        "returned": len(rows),
        "truncated": total > len(rows),
        "basis": BASIS,
        "data_version": data_version(corpus=True),
        "findings": rows,
    }
    out = fit(payload, MAX_LIST_BYTES, ("findings",))
    out["returned"] = len(out["findings"])
    out["truncated"] = total > out["returned"]
    if capped:
        out["limits"]["response_truncated"] = True
    return out


def advisory_exposure(arguments: dict[str, Any]) -> dict[str, Any]:
    inputs = _read_input(arguments)
    if inputs["cve_id"] is None:
        return _list(inputs)
    return _single(inputs)


def register(mcp) -> None:
    mcp.add_public_tool(NAME, DESCRIPTION, SCHEMA, advisory_exposure)
