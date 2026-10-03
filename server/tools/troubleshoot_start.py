import ipaddress
import json
import re
from typing import Any

import yaml

from common.validate import ToolInputError, check_fields, check_size
from engines.triage import catalog, loaders, select, signals
from engines.triage.triage import _clause_order, _fill
from engines.triage.triage_readonly import _is_read_only
from server.data import data_dir, data_version
from server.startup import SHIPPING_ISSUES

NAME = "troubleshoot_start"
VENDORS = ("arista_eos", "cisco_ios", "juniper_junos")
BASIS = "ordered from the issue procedure; no model"
MAX_CHECKS = 16
MAX_RESPONSE_BYTES = 12 * 1024
MAX_SYMPTOM_BYTES = 200
MAX_CONTEXT_BYTES = 200
COST_ORDER = {"cheap": 0, "moderate": 1, "expensive": 2}
ALL_READABLE = "every step in this procedure has an evidence rule"
INTERFACE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9/._:-]{0,63}")

DESCRIPTION = (
    "Start troubleshooting a network problem: give a symptom and a vendor, get the ordered "
    "read-only checks to run on the device, each with its command, what it can show and whether "
    "the command has run on real hardware. Symptoms: bgp-session-down, ospf-neighbor-down, "
    "interface-degraded (only procedures verified on real devices are accepted). Vendors: "
    + ", ".join(VENDORS)
    + ". Optional context fills the interface or peer address into the commands. Run the checks, "
    "then pass their output to troubleshoot_analyze."
)

SCHEMA = {
    "type": "object",
    "properties": {
        "symptom": {
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_SYMPTOM_BYTES,
            "description": "bgp-session-down, ospf-neighbor-down or interface-degraded.",
        },
        "vendor": {"type": "string", "enum": list(VENDORS)},
        "context": {
            "type": "object",
            "properties": {
                "interface": {"type": "string", "maxLength": MAX_CONTEXT_BYTES},
                "peer_ip": {"type": "string", "maxLength": MAX_CONTEXT_BYTES},
            },
            "additionalProperties": False,
        },
    },
    "required": ["symptom", "vendor"],
    "additionalProperties": False,
}

EXAMPLES = {
    NAME: [
        {"symptom": "ospf-neighbor-down", "vendor": "cisco_ios"},
        {"symptom": "interface-degraded", "vendor": "juniper_junos"},
        {
            "symptom": "ospf-neighbor-down",
            "vendor": "arista_eos",
            "context": {"interface": "Ethernet1", "peer_ip": "192.0.2.2"},
        },
    ]
}


def _issues() -> dict[str, dict]:
    return {doc["issue"]["key"]: doc for doc in loaders.load_issues() if doc["issue"].get("key")}


def supported_symptoms() -> list[str]:
    issues = _issues()
    return sorted(
        key for key in SHIPPING_ISSUES if key in issues and issues[key]["issue"].get("verified")
    )


def _aliases() -> dict[str, str]:
    path = data_dir() / "sop" / "symptom_aliases.yaml"
    if not path.is_file():
        return {}
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    table = doc.get("aliases", doc) if isinstance(doc, dict) else None
    if not isinstance(table, dict):
        return {}
    return {
        " ".join(alias.lower().split()): key
        for alias, key in table.items()
        if isinstance(alias, str) and isinstance(key, str)
    }


def resolve_symptom(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ToolInputError("invalid_value", field="symptom")
    check_size(value, MAX_SYMPTOM_BYTES, "symptom")
    spoken = " ".join(value.lower().split())
    supported = supported_symptoms()
    key = spoken if spoken in SHIPPING_ISSUES else _aliases().get(spoken)
    if key not in supported:
        raise ToolInputError("unsupported_symptom", supported=supported, field="symptom")
    return key


def _vendor(value: Any) -> str:
    if not isinstance(value, str):
        raise ToolInputError("invalid_value", field="vendor")
    if value not in VENDORS:
        raise ToolInputError("unsupported_vendor", supported=list(VENDORS), field="vendor")
    return value


def _context(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ToolInputError("invalid_value", field="context")
    for name in sorted(value):
        if name not in ("interface", "peer_ip"):
            raise ToolInputError("unknown_field", field=f"context.{name}")
        if not isinstance(value[name], str):
            raise ToolInputError("invalid_value", field=f"context.{name}")
        check_size(value[name], MAX_CONTEXT_BYTES, f"context.{name}")
    params = {}
    interface = value.get("interface", "").strip()
    if interface:
        if not INTERFACE_NAME.fullmatch(interface):
            raise ToolInputError("invalid_value", field="context.interface")
        params["ifname"] = params["ospf_if"] = interface
    peer = value.get("peer_ip", "").strip()
    if peer:
        try:
            params["peer_ip"] = str(ipaddress.ip_address(peer))
        except ValueError:
            raise ToolInputError("invalid_value", field="context.peer_ip") from None
    return params


def ordered_checks(issue: str) -> list[str]:
    pool = select.checks_for_issue(issue)
    clauses = _clause_order(issue)
    openers = [c for c in select.opening_checks() if c in pool and c not in clauses]
    rest = sorted(
        pool - set(openers),
        key=lambda c: (
            clauses.get(c, (99, 99)),
            COST_ORDER.get(signals.cost_of(c), 9),
            select.layer_of(c) or 99,
            c,
        ),
    )
    return [c for c in openers + rest if signals.shape_of(c) is not None]


def _reads(capability: str) -> list[str]:
    spec = signals.load_signals().get(capability) or {}
    return [s["name"] for s in spec.get("signals") or [] if isinstance(s, dict) and s.get("name")]


def _note(unreadable: int, missing_command: int, refused: int, over_cap: int) -> str:
    parts = []
    if unreadable:
        parts.append(
            f"{unreadable} step(s) in this procedure have no evidence rule and are omitted"
        )
    if missing_command:
        parts.append(f"{missing_command} check(s) have no command catalogued for this vendor")
    if refused:
        parts.append(f"{refused} check(s) were refused because they are not read-only")
    if over_cap:
        parts.append(f"{over_cap} check(s) were cut by the {MAX_CHECKS}-check limit")
    return "; ".join(parts) if parts else ALL_READABLE


def troubleshoot_start(arguments: dict[str, Any]) -> dict[str, Any]:
    check_fields(arguments, required=("symptom", "vendor"), optional=("context",))
    key = resolve_symptom(arguments["symptom"])
    vendor = _vendor(arguments["vendor"])
    params = _context(arguments.get("context"))

    doc = _issues()[key]
    spec = doc["issue"]
    procedures = doc.get("procedures") or ([doc["procedure"]] if doc.get("procedure") else [])
    steps = [s for p in procedures if isinstance(p, dict) for s in p.get("steps") or []]
    by_capability = {}
    for step in steps:
        by_capability.setdefault(step.get("capability"), step)
    total = len(steps)
    readable = sum(1 for s in steps if signals.shape_of(s.get("capability")) is not None)
    issue = {
        "key": key,
        "label": spec.get("label") or "",
        "verified": bool(spec.get("verified")),
        "sop_refs": list(spec.get("sop_refs") or []),
    }

    cat = catalog.current()
    checks = []
    missing_command = refused = over_cap = 0
    for capability in ordered_checks(key):
        command = cat.command_for(capability, vendor)
        if command is None:
            missing_command += 1
            continue
        text, _missing = _fill(command.command, params, set(command.params))
        is_check = (cat.capabilities.get(capability) or {}).get("kind") == "check"
        if not is_check or not _is_read_only(command.command) or not _is_read_only(text):
            refused += 1
            continue
        if len(checks) == MAX_CHECKS:
            over_cap += 1
            continue
        step = by_capability.get(capability) or {}
        described = (cat.capabilities.get(capability) or {}).get("description") or ""
        checks.append(
            {
                "order": len(checks) + 1,
                "capability": capability,
                "command": text,
                "description": step.get("sop_step_title") or described,
                "why": step.get("description") or described,
                "reads": _reads(capability),
                "hardware_verified": command.hardware_verified,
            }
        )

    common = {"basis": BASIS, "data_version": data_version(corpus=False)}
    if not checks:
        return {"status": "no_commands_for_vendor", "issue": issue, "vendor": vendor, **common}
    answer = {
        "status": "checks",
        "issue": issue,
        "checks": checks,
        "total_steps": total,
        "readable_steps": readable,
        "note": _note(total - readable, missing_command, refused, over_cap),
        **common,
    }
    if len(json.dumps(answer, ensure_ascii=False).encode("utf-8")) > MAX_RESPONSE_BYTES:
        raise ValueError("the check list exceeds the response cap")
    return answer


def register(mcp) -> None:
    mcp.add_public_tool(NAME, DESCRIPTION, SCHEMA, troubleshoot_start)
