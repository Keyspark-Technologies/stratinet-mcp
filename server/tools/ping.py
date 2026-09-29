from typing import Any

from common.validate import check_fields

SCHEMA = {"type": "object", "properties": {}, "additionalProperties": False}

EXAMPLES = {"ping": [{}]}


def ping(arguments: dict[str, Any]) -> dict[str, Any]:
    check_fields(arguments)
    return {"result": "pong"}


def register(mcp) -> None:
    mcp.add_public_tool("ping", "Returns 'pong'. Confirms the server is reachable.", SCHEMA, ping)
