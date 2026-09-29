import pytest
from mcp.client import Client

from common.validate import ToolInputError
from server.errors import MESSAGES, error_payload
from server.main import build_server

pytestmark = pytest.mark.anyio

CONTRACT_CODES = {
    "missing_field",
    "invalid_value",
    "unknown_field",
    "input_too_large",
    "unsupported_vendor",
    "unsupported_symptom",
    "malformed_cve_id",
    "invalid_feature_fact",
}
SENTINEL = "caller-value-7f3a"


def wrong_type(prop):
    return {"string": 7, "integer": SENTINEL, "number": SENTINEL, "boolean": SENTINEL}.get(
        prop.get("type"), {"unexpected": SENTINEL}
    )


async def bad_calls(client):
    for tool in (await client.list_tools()).tools:
        schema = tool.input_schema
        props = schema.get("properties", {})
        example = {name: None for name in schema.get("required", [])}
        yield tool.name, "unknown_field", {**example, "rule_name": SENTINEL}
        for name in schema.get("required", []):
            yield tool.name, "missing_field", {k: v for k, v in example.items() if k != name}
        for name, prop in props.items():
            yield tool.name, "wrong_type", {**example, name: wrong_type(prop)}


async def test_bad_input_returns_only_contract_errors(settings):
    async with Client(build_server(settings)) as client:
        calls = [call async for call in bad_calls(client)]
        assert calls
        for tool, kind, args in calls:
            result = await client.call_tool(tool, args)
            error = result.structured_content["error"]
            assert result.is_error, (tool, kind)
            assert error["code"] in CONTRACT_CODES, (tool, kind, error)
            assert error["message"] == MESSAGES[error["code"]]
            assert SENTINEL not in result.content[0].text
            assert set(result.structured_content) == {"error"}


async def test_unknown_field_is_named(settings):
    async with Client(build_server(settings)) as client:
        result = await client.call_tool("ping", {"rule_name": "x"})
    error = {"code": "unknown_field", "message": MESSAGES["unknown_field"], "field": "rule_name"}
    assert result.structured_content == {"error": error}


def test_supported_values_are_sorted():
    payload = error_payload(ToolInputError("unsupported_vendor", supported=["b", "a"]))
    assert payload["error"]["supported"] == ["a", "b"]


def test_an_unknown_code_becomes_internal_error():
    assert error_payload(ToolInputError("made_up_code"))["error"]["code"] == "internal_error"


def test_the_callers_message_is_never_returned():
    payload = error_payload(ToolInputError("invalid_value", message=f"got {SENTINEL}"))
    assert SENTINEL not in str(payload)
