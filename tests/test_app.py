import json
import socket
import urllib.error
import urllib.parse
import urllib.request

import pytest
from mcp.client import Client

from server.main import MAX_REQUEST_BODY_BYTES, build_server

pytestmark = pytest.mark.anyio

LIST_TOOLS = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).encode()


def http(url, method="GET", body=None, headers=None):
    req = urllib.request.Request(url, method=method, data=body, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


async def test_client_lists_and_calls_ping(live_server):
    async with Client(f"{live_server}/mcp") as client:
        tools = await client.list_tools()
        result = await client.call_tool("ping", {})

    assert [t.name for t in tools.tools] == ["ping"]
    assert tools.tools[0].input_schema["additionalProperties"] is False
    assert not result.is_error
    assert result.structured_content == {"result": "pong"}
    assert json.loads(result.content[0].text) == result.structured_content


async def test_crash_does_not_reach_the_caller(settings):
    mcp = build_server(settings)

    def boom(arguments):
        raise RuntimeError("internal detail that must not reach the caller")

    mcp.add_public_tool("boom", "Fails.", {"type": "object", "additionalProperties": False}, boom)

    async with Client(mcp) as client:
        result = await client.call_tool("boom", {})

    assert result.is_error
    assert result.structured_content == {
        "error": {"code": "internal_error", "message": "The tool could not complete this request."}
    }
    assert "internal detail" not in result.content[0].text


async def test_an_answer_carrying_an_internal_marker_is_withheld(settings):
    mcp = build_server(settings)

    def leaky(arguments):
        return {"detail": "Traceback (most recent call last): /app/server.py"}

    mcp.add_public_tool("leaky", "Leaks.", {"type": "object", "additionalProperties": False}, leaky)

    async with Client(mcp) as client:
        result = await client.call_tool("leaky", {})

    assert result.is_error
    assert result.structured_content["error"]["code"] == "internal_error"
    assert "Traceback" not in result.content[0].text


async def test_healthz(live_server):
    status, body = http(f"{live_server}/healthz")
    assert status == 200
    assert json.loads(body) == {"status": "ok"}


async def test_unknown_host_is_refused(live_server):
    headers = {
        "Host": "attacker.example",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    status, _ = http(f"{live_server}/mcp", "POST", LIST_TOOLS, headers)
    assert status == 421


def status_of_raw_request(base_url, request):
    url = urllib.parse.urlsplit(base_url)
    with socket.create_connection((url.hostname, url.port), timeout=10) as sock:
        sock.sendall(request)
        status_line = sock.makefile("rb").readline()
    return int(status_line.split()[1])


async def test_oversized_body_is_refused(live_server):
    host = urllib.parse.urlsplit(live_server).netloc
    request = (
        f"POST /mcp HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/json\r\n"
        f"Accept: application/json, text/event-stream\r\n"
        f"Content-Length: {MAX_REQUEST_BODY_BYTES + 1}\r\n\r\n"
    ).encode()
    assert status_of_raw_request(live_server, request) == 413


async def test_server_identifies_as_stratinet(settings):
    async with Client(build_server(settings)) as client:
        assert client.server_info.name == "stratinet"
