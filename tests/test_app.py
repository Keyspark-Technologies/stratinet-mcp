import json
import urllib.error
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
    assert not result.is_error
    assert result.content[0].text == "pong"


async def test_crash_does_not_reach_the_caller(settings):
    mcp = build_server(settings)

    @mcp.tool()
    def boom() -> str:
        raise RuntimeError("internal detail that must not reach the caller")

    async with Client(mcp) as client:
        result = await client.call_tool("boom", {})

    assert result.is_error
    assert result.content[0].text == "Error executing tool boom"


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


async def test_oversized_body_is_refused(live_server):
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    status, _ = http(f"{live_server}/mcp", "POST", b"x" * (MAX_REQUEST_BODY_BYTES + 1), headers)
    assert status == 413


async def test_server_identifies_as_stratinet(settings):
    async with Client(build_server(settings)) as client:
        assert client.server_info.name == "stratinet"
