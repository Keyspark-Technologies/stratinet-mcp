import json
from typing import Any

from common.validate import ToolInputError, check_fields, check_size
from engines.triage import catalog
from server.data import data_version

NAME = "translate_diagnostic"
VENDORS = (
    "arista_eos",
    "cisco_ios",
    "fortinet_fortianalyzer",
    "fortinet_fortimanager",
    "fortinet_fortios",
    "fortinet_fortiswitch",
    "juniper_junos",
    "paloalto_panos",
)
BASIS = "catalogued capability→command mapping; no model"
MAX_CAPABILITY_BYTES = 200
MAX_COMMANDS = 8
MAX_RESPONSE_BYTES = 8 * 1024

DESCRIPTION = (
    "Translate a read-only network diagnostic into another vendor's CLI. Give a capability "
    "such as check-bgp-summary and one or more target vendors; get the catalogued command for "
    "each vendor, whether it has been run on real hardware, and which vendors have it. If the "
    "capability is unknown, returns close capability names. Never returns configuration "
    "commands. Vendors: " + ", ".join(VENDORS) + "."
)

SCHEMA = {
    "type": "object",
    "properties": {
        "capability": {
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_CAPABILITY_BYTES,
            "description": "Capability key, for example check-bgp-summary.",
        },
        "target_vendor": {
            "description": "One vendor slug, or a list of them.",
            "oneOf": [
                {"type": "string", "enum": list(VENDORS)},
                {
                    "type": "array",
                    "items": {"type": "string", "enum": list(VENDORS)},
                    "minItems": 1,
                    "maxItems": len(VENDORS),
                    "uniqueItems": True,
                },
            ],
        },
    },
    "required": ["capability", "target_vendor"],
    "additionalProperties": False,
}

EXAMPLES = {
    NAME: [
        {"capability": "check-bgp-summary", "target_vendor": ["fortinet_fortios"]},
        {"capability": "check-bgp-summary", "target_vendor": "juniper_junos"},
        {"capability": "check-optical-levels", "target_vendor": ["fortinet_fortios"]},
        {"capability": "check-bgp-sum", "target_vendor": "cisco_ios"},
    ]
}


def _capability(arguments: dict[str, Any]) -> str:
    value = arguments["capability"]
    if not isinstance(value, str) or not value.strip():
        raise ToolInputError("invalid_value", field="capability")
    check_size(value, MAX_CAPABILITY_BYTES, "capability")
    return value.strip()


def _vendors(arguments: dict[str, Any]) -> list[str]:
    value = arguments["target_vendor"]
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not values or len(values) > len(VENDORS):
        raise ToolInputError("invalid_value", field="target_vendor")
    if len(set(map(repr, values))) != len(values):
        raise ToolInputError("invalid_value", field="target_vendor")
    for vendor in values:
        if not isinstance(vendor, str):
            raise ToolInputError("invalid_value", field="target_vendor")
        if vendor not in VENDORS:
            raise ToolInputError(
                "unsupported_vendor", supported=list(VENDORS), field="target_vendor"
            )
    return values


def translate_diagnostic(arguments: dict[str, Any]) -> dict[str, Any]:
    check_fields(arguments, required=("capability", "target_vendor"))
    capability = _capability(arguments)
    vendors = _vendors(arguments)
    answer = catalog.current().translate(capability, vendors)
    if len(answer.get("commands", ())) > MAX_COMMANDS:
        raise ValueError("translation exceeds the command cap")
    answer["basis"] = BASIS
    answer["data_version"] = data_version(corpus=False)
    if len(json.dumps(answer, ensure_ascii=False).encode("utf-8")) > MAX_RESPONSE_BYTES:
        raise ValueError("translation exceeds the response cap")
    return answer


def register(mcp) -> None:
    mcp.add_public_tool(NAME, DESCRIPTION, SCHEMA, translate_diagnostic)
