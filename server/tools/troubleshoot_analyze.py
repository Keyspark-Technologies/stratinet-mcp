import asyncio
from typing import Any

from common.project import ResponseTooLarge, fit, response_size
from common.validate import (
    MAX_OUTPUT_BYTES,
    MAX_OUTPUTS,
    ToolInputError,
    check_enum,
    check_fields,
    check_outputs,
    check_size,
)
from engines.triage import catalog, findings, select, signals
from engines.triage.extract import ERROR, NOT_CONFIGURED, OK_EMPTY, UNLICENSED, UNPARSEABLE
from engines.triage.triage import NOTHING_PROVABLE, _fill, _signal_means, triage
from engines.triage.triage_readonly import _is_read_only
from server.data import data_version
from server.tools.troubleshoot_start import (
    VENDORS,
    _context,
    _issues,
    ordered_checks,
    resolve_symptom,
)

NAME = "troubleshoot_analyze"
BASIS = "deterministic — authored predicates over parsed device output; no model"
STAMPED_BASIS = (
    "ranked over the evidence supplied; {count} check(s) that could have outranked it "
    "were not available"
)
LEADING_NOTE = "this is the strongest reading so far, NOT a verdict"
ROLES = ("local", "peer")
OUTPUT_FIELDS = ("command", "output", "device_role")
MAX_SYMPTOM_BYTES = 200
MAX_COMMAND_BYTES = 256
MAX_CONTEXT_KEYS = 8
MAX_READ = 12
MAX_NEED = 3
MAX_LINE_CHARS = 400
MAX_RESPONSE_BYTES = 16 * 1024
LOG_SHAPE = "log_lines"
DEVICE_STATUSES = (UNLICENSED, NOT_CONFIGURED, ERROR)

NO_COMMAND = "no catalogued command matches this on {vendor}"
NO_RULE = "the catalogued command has no evidence rule, so its output cannot be read"
UNREADABLE = "the deterministic parsers could not read this output; nothing is taken from it"
NOTHING_TO_READ = "the output holds nothing to read; it is not read as health"
DEVICE_SAID = "device returned '{line}' — no state to read from it"
NO_RULE_MATCHED = "the output was parsed but no authored rule matched it; it is not read as health"
PEER_WHY = (
    "run this on the peer device and pass it with device_role peer: {capability} compares "
    "both ends and only one end has been read"
)
FAR_END_WHY = "names the device on the far end of the link, so the same check can be read there"
RERUN_UNREAD = "the output supplied for this check could not be read; paste the complete output"
RERUN_HEALTHY = (
    "the output supplied for this check showed no fault; run it again while the problem "
    "is occurring"
)

DESCRIPTION = (
    "Analyze pasted output of read-only troubleshooting commands for one network problem. "
    "Give the vendor, the symptom (bgp-session-down, ospf-neighbor-down or interface-degraded) "
    "and up to 8 outputs, each with the command that produced it and whether it came from the "
    "local or the peer device. Returns root_cause with the proving line, need_more_evidence "
    "with the strongest reading so far and up to 3 commands to run next, or cannot_determine "
    "with what would settle it. Outputs that could not be read are listed in unread and never "
    "count as health. Vendors: " + ", ".join(VENDORS) + ". Set evidence_complete when the device "
    "cannot be reached again; the answer then says which checks were missing."
)

SCHEMA = {
    "type": "object",
    "properties": {
        "vendor": {"type": "string", "enum": list(VENDORS)},
        "symptom": {
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_SYMPTOM_BYTES,
            "description": "bgp-session-down, ospf-neighbor-down or interface-degraded.",
        },
        "outputs": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_OUTPUTS,
            "items": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "minLength": 1, "maxLength": MAX_COMMAND_BYTES},
                    "output": {"type": "string"},
                    "device_role": {"type": "string", "enum": list(ROLES)},
                },
                "required": list(OUTPUT_FIELDS),
                "additionalProperties": False,
            },
        },
        "context": {
            "type": "object",
            "maxProperties": MAX_CONTEXT_KEYS,
            "properties": {
                "interface": {"type": "string", "maxLength": 200},
                "peer_ip": {"type": "string", "maxLength": 200},
            },
            "additionalProperties": False,
        },
        "evidence_complete": {"type": "boolean", "default": False},
        "include_remediation": {"type": "boolean", "default": False},
    },
    "required": ["vendor", "symptom", "outputs"],
    "additionalProperties": False,
}

OSPF_NEIGHBOR = (
    "Neighbor ID     Pri   State           Dead Time   Address         Interface\n"
    "192.0.2.2         1   EXSTART/DR      00:00:33    192.0.2.2       GigabitEthernet0/1\n"
)

EXAMPLES = {
    NAME: [
        {
            "vendor": "cisco_ios",
            "symptom": "ospf-neighbor-down",
            "outputs": [
                {
                    "command": "show ip ospf neighbor",
                    "output": OSPF_NEIGHBOR,
                    "device_role": "local",
                }
            ],
        },
        {
            "vendor": "juniper_junos",
            "symptom": "bgp-session-down",
            "outputs": [
                {
                    "command": "show bgp summary",
                    "output": "Warning: License key missing; BGP is not running\n",
                    "device_role": "local",
                },
                {
                    "command": "show route protocol bgp",
                    "output": "inet.0: 4 destinations, 4 routes (4 active, 0 holddown, 0 hidden)\n",
                    "device_role": "local",
                },
            ],
        },
        {
            "vendor": "cisco_ios",
            "symptom": "ospf-neighbor-down",
            "outputs": [
                {"command": "sh ip ospf nei", "output": OSPF_NEIGHBOR, "device_role": "local"}
            ],
            "context": {"interface": "GigabitEthernet0/1"},
            "evidence_complete": True,
            "include_remediation": True,
        },
    ]
}


def _flag(arguments: dict[str, Any], name: str) -> bool:
    value = arguments.get(name, False)
    if not isinstance(value, bool):
        raise ToolInputError("invalid_value", field=name)
    return value


def _params(value: Any) -> dict[str, str]:
    if isinstance(value, dict) and len(value) > MAX_CONTEXT_KEYS:
        raise ToolInputError("input_too_large", field="context")
    return _context(value)


def _clip(text: str, keep_tail: bool) -> tuple[str, bool]:
    data = text.encode("utf-8")
    if len(data) <= MAX_OUTPUT_BYTES:
        return text, False
    if keep_tail:
        kept = data[-MAX_OUTPUT_BYTES:].decode("utf-8", "ignore")
        return (kept.split("\n", 1)[1] if "\n" in kept else kept), True
    kept = data[:MAX_OUTPUT_BYTES].decode("utf-8", "ignore")
    return (kept.rsplit("\n", 1)[0] if "\n" in kept else kept), True


def _outputs(value: Any, vendor: str, cat: catalog.Catalog) -> tuple[list[dict], bool]:
    if not isinstance(value, list) or not value:
        raise ToolInputError("invalid_value", field="outputs")
    if len(value) > MAX_OUTPUTS:
        raise ToolInputError("input_too_large", field="outputs")
    supplied = []
    truncated = False
    for index, item in enumerate(value):
        field = f"outputs[{index}]"
        if not isinstance(item, dict):
            raise ToolInputError("invalid_value", field=field)
        for name in sorted(item):
            if name not in OUTPUT_FIELDS:
                raise ToolInputError("unknown_field", field=f"{field}.{name}")
        for name in OUTPUT_FIELDS:
            if name not in item:
                raise ToolInputError("missing_field", field=f"{field}.{name}")
        command, output, role = (item[name] for name in OUTPUT_FIELDS)
        if not isinstance(command, str) or not command.strip():
            raise ToolInputError("invalid_value", field=f"{field}.command")
        check_size(command, MAX_COMMAND_BYTES, f"{field}.command")
        if not isinstance(output, str):
            raise ToolInputError("invalid_value", field=f"{field}.output")
        if not isinstance(role, str) or role not in ROLES:
            raise ToolInputError("invalid_value", field=f"{field}.device_role")
        command = " ".join(command.split())
        matched = cat.capabilities_for(vendor, command)
        shaped = [c for c in matched if signals.shape_of(c) is not None]
        text, cut = _clip(output, any(signals.shape_of(c) == LOG_SHAPE for c in shaped))
        truncated = truncated or cut
        supplied.append(
            {
                "command": command,
                "output": text,
                "origin": role,
                "matched": matched,
                "capabilities": shaped,
            }
        )
    check_outputs([item["output"] for item in supplied])
    return supplied, truncated


def _observations(supplied: list[dict]) -> tuple[list[dict], list[int]]:
    observations, owners = [], []
    order = sorted(range(len(supplied)), key=lambda i: (supplied[i]["origin"] != "local", i))
    for index in order:
        item = supplied[index]
        for capability in item["capabilities"]:
            observations.append(
                {
                    "capability": capability,
                    "command": item["command"],
                    "output": item["output"],
                    "origin": item["origin"],
                }
            )
            owners.append(index)
    return observations, owners


def _entries_by_output(supplied: list[dict], trail: list[dict], owners: list[int]) -> list[list]:
    by_output: list[list[dict]] = [[] for _ in supplied]
    for position, owner in enumerate(owners):
        by_output[owner].append(trail[position])
    for entry in trail[len(owners) :]:
        for index, item in enumerate(supplied):
            if entry.get("reused") == item["command"]:
                by_output[index].append(entry)
    return by_output


def _unread_why(item: dict, entries: list[dict], vendor: str) -> str:
    if not item["matched"]:
        return NO_COMMAND.format(vendor=vendor)
    if not entries:
        return NO_RULE
    first = entries[0]
    status = first.get("status")
    if status in DEVICE_STATUSES and first.get("evidence"):
        return DEVICE_SAID.format(line=first["evidence"])
    if status == UNPARSEABLE:
        return UNREADABLE
    if status == OK_EMPTY:
        return NOTHING_TO_READ
    return NO_RULE_MATCHED


def _steps(issue: str) -> dict[str, dict]:
    doc = _issues()[issue]
    procedures = doc.get("procedures") or ([doc["procedure"]] if doc.get("procedure") else [])
    steps: dict[str, dict] = {}
    for procedure in procedures:
        if not isinstance(procedure, dict):
            continue
        for step in procedure.get("steps") or []:
            if isinstance(step, dict):
                steps.setdefault(step.get("capability"), step)
    return steps


def _command(cat: catalog.Catalog, capability: str, vendor: str, params: dict) -> str | None:
    command = cat.command_for(capability, vendor)
    if command is None:
        return None
    text, _missing = _fill(command.command, params, set(command.params))
    is_check = (cat.capabilities.get(capability) or {}).get("kind") == "check"
    if not is_check or not _is_read_only(command.command) or not _is_read_only(text):
        return None
    return text


def _why(cat: catalog.Catalog, steps: dict[str, dict], capability: str) -> str:
    step = steps.get(capability) or {}
    described = (cat.capabilities.get(capability) or {}).get("description")
    return step.get("description") or described or signals.describe(capability)


def _need(
    result: dict,
    issue: str,
    vendor: str,
    cat: catalog.Catalog,
    ran: set[str],
    unread: set[str],
    healthy: set[str],
    prefer: frozenset[str],
) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    params = result.get("params") or {}
    steps = _steps(issue)

    def add(command: str | None, why: str) -> None:
        if command and command not in seen and len(rows) < MAX_NEED:
            seen.add(command)
            rows.append({"command": command, "why": why})

    step = result.get("next") or {}
    if step and "menu" not in step and _is_read_only(step.get("command") or ""):
        why = PEER_WHY if step.get("origin") == "peer" else FAR_END_WHY
        add(step.get("command"), why.format(capability=step.get("capability") or ""))
    menu = sorted(step.get("menu") or [], key=lambda c: c not in prefer)
    deferred = [d["capability"] for d in result.get("deferred") or []]
    for capability in menu + deferred:
        add(_command(cat, capability, vendor, params), _why(cat, steps, capability))
    order = ordered_checks(issue)
    tiers = (
        ([c for c in order if c not in ran], None),
        ([c for c in order if c in unread], RERUN_UNREAD),
        ([c for c in order if c in healthy], RERUN_HEALTHY),
    )
    for capabilities, why in tiers:
        if rows:
            break
        for capability in capabilities:
            add(_command(cat, capability, vendor, params), why or _why(cat, steps, capability))
    return rows


def _explanation(cause: str, means: str, root: dict, vendor: str, explained: int) -> str:
    parts = [means] if means else []
    parts.append(
        f"Proved by '{root.get('command')}' ({root.get('capability')}) on {vendor}, "
        f"read as {cause}: '{root.get('evidence') or ''}'"
    )
    if explained:
        parts.append(f"{explained} other reading(s) are explained by this cause.")
    return " ".join(parts)


def _finding(ranked: dict, vendor: str, basis: str, include_remediation: bool) -> dict:
    root = ranked["root_cause"]
    cause = root["signal"]
    means = _signal_means(cause)
    finding = {
        "cause": cause,
        "means": means,
        "explanation": _explanation(cause, means, root, vendor, len(ranked["symptoms"])),
        "evidence": {"command": root.get("command"), "line": root.get("evidence") or ""},
        "symptoms": [
            {"cause": t["signal"], "line": t.get("evidence") or ""} for t in ranked["symptoms"]
        ],
        "also_found": [
            {"cause": t["signal"], "line": t.get("evidence") or ""} for t in ranked["also"]
        ],
        "basis": basis,
    }
    if include_remediation:
        finding["remediation_options"] = []
    return finding


def _outranking(issue: str, primary: str, ran: set[str], cat: catalog.Catalog, vendor: str):
    unrun = {
        c
        for c in select.checks_for_issue(issue)
        if c not in ran and signals.shape_of(c) is not None and cat.command_for(c, vendor)
    }
    return frozenset(findings.outrankers(primary, unrun))


def _fit(answer: dict) -> dict:
    try:
        return fit(answer, MAX_RESPONSE_BYTES, ("read",))
    except ResponseTooLarge:
        pass
    trimmed = {**answer, "read": []}
    finding = trimmed.get("finding")
    if isinstance(finding, dict):
        finding = trimmed["finding"] = {
            **finding,
            "also_found": list(finding["also_found"]),
            "symptoms": list(finding["symptoms"]),
        }
        for name in ("also_found", "symptoms"):
            while finding[name] and response_size(trimmed) > MAX_RESPONSE_BYTES:
                finding[name].pop()
    fitted = fit(trimmed, MAX_RESPONSE_BYTES, ())
    fitted["limits"]["response_truncated"] = True
    return fitted


def troubleshoot_analyze(arguments: dict[str, Any]) -> dict[str, Any]:
    check_fields(
        arguments,
        required=("vendor", "symptom", "outputs"),
        optional=("context", "evidence_complete", "include_remediation"),
    )
    vendor = check_enum(arguments["vendor"], VENDORS, "vendor")
    issue = resolve_symptom(arguments["symptom"])
    params = _params(arguments.get("context"))
    evidence_complete = _flag(arguments, "evidence_complete")
    include_remediation = _flag(arguments, "include_remediation")
    cat = catalog.current()
    supplied, outputs_truncated = _outputs(arguments["outputs"], vendor, cat)

    observations, owners = _observations(supplied)
    request = {"vendor": vendor, "issue": issue, "observations": observations, "params": params}
    result = asyncio.run(triage(None, request))
    trail = result["trail"]

    clipped = False
    for entry in trail:
        evidence = entry.get("evidence") or ""
        if len(evidence) > MAX_LINE_CHARS:
            entry["evidence"] = evidence[:MAX_LINE_CHARS]
            clipped = True

    read_rows = [
        {"command": t.get("command"), "read_as": t["signal"], "line": t.get("evidence") or ""}
        for t in trail
        if t.get("signal")
    ]
    if len(read_rows) > MAX_READ:
        read_rows = read_rows[:MAX_READ]
        clipped = True

    unread_caps: set[str] = set()
    unread_rows = []
    for item, entries in zip(supplied, _entries_by_output(supplied, trail, owners), strict=True):
        if not any(e.get("signal") for e in entries):
            unread_caps.update(item["capabilities"])
            why = _unread_why(item, entries, vendor)
            unread_rows.append({"command": item["command"], "why": why})
    ran = {t["capability"] for t in trail}
    faulted = {t["capability"] for t in trail if findings.is_fault(t.get("signal"))}
    healthy = {t["capability"] for t in trail if t.get("signal")} - faulted
    known = (result, issue, vendor, cat, ran, unread_caps, healthy)

    ranked = findings.rank(trail)
    root = ranked["root_cause"]
    if result.get("root_cause") and root:
        answer = {"status": "root_cause", "vendor": vendor, "symptom": issue}
        answer["finding"] = _finding(ranked, vendor, BASIS, include_remediation)
    elif root and evidence_complete:
        missing = _outranking(issue, root["signal"], ran, cat, vendor)
        basis = STAMPED_BASIS.format(count=len(missing))
        answer = {"status": "root_cause", "vendor": vendor, "symptom": issue}
        answer["finding"] = _finding(ranked, vendor, basis, include_remediation)
        answer["need"] = _need(*known, missing)
    elif root:
        answer = {"status": "need_more_evidence", "vendor": vendor, "symptom": issue}
        answer["leading_finding"] = {
            "cause": root["signal"],
            "line": root.get("evidence") or "",
            "note": LEADING_NOTE,
        }
        answer["need"] = _need(*known, frozenset())
    else:
        answer = {"status": "cannot_determine", "vendor": vendor, "symptom": issue}
        answer["reason"] = NOTHING_PROVABLE
        answer["need"] = _need(*known, frozenset())
        if not answer["need"]:
            raise ValueError("cannot_determine needs at least one next command")

    answer["read"] = read_rows
    answer["unread"] = unread_rows
    answer["limits"] = {"outputs_truncated": outputs_truncated, "response_truncated": False}
    answer["basis"] = BASIS
    answer["data_version"] = data_version(corpus=False)
    fitted = _fit(answer)
    if clipped:
        fitted["limits"]["response_truncated"] = True
    return fitted


def register(mcp) -> None:
    mcp.add_public_tool(NAME, DESCRIPTION, SCHEMA, troubleshoot_analyze)
