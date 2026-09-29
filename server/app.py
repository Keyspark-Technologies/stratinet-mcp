import asyncio
import json
import logging
import traceback
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS, CallToolResult, TextContent
from mcp.types import Tool as MCPTool

from common.redact import assert_no_internal_markers
from common.validate import ToolInputError
from server.errors import error_payload

logger = logging.getLogger(__name__)

Handler = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class PublicTool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Handler


class StratinetServer(MCPServer):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._public_tools: dict[str, PublicTool] = {}

    def add_public_tool(
        self, name: str, description: str, input_schema: Mapping[str, Any], handler: Handler
    ) -> None:
        if name in self._public_tools:
            raise ValueError(f"tool {name!r} is registered twice")
        if input_schema.get("additionalProperties") is not False:
            raise ValueError(f"tool {name!r} must set additionalProperties to false")
        self._public_tools[name] = PublicTool(name, description, dict(input_schema), handler)

    async def list_tools(self) -> list[MCPTool]:
        return [
            MCPTool(name=t.name, description=t.description, input_schema=t.input_schema)
            for t in self._public_tools.values()
        ]

    async def call_tool(self, name: str, arguments: dict[str, Any], context: Any = None):
        tool = self._public_tools.get(name)
        if tool is None:
            raise MCPError(INVALID_PARAMS, "Unknown tool")
        try:
            payload = await asyncio.to_thread(tool.handler, dict(arguments or {}))
            assert_no_internal_markers(payload, check_private_ips=False)
            return _result(payload, is_error=False)
        except ToolInputError as exc:
            payload = error_payload(exc)
        except Exception as exc:
            logger.error(
                "tool %r failed with %s\n%s",
                name,
                type(exc).__name__,
                "".join(traceback.format_tb(exc.__traceback__)),
            )
            payload = error_payload(exc)
        assert_no_internal_markers(payload)
        return _result(payload, is_error=True)


def _result(payload: dict[str, Any], *, is_error: bool) -> CallToolResult:
    text = json.dumps(payload, ensure_ascii=False)
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        structured_content=payload,
        is_error=is_error,
    )
