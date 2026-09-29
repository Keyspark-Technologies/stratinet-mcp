import socket

import pytest
from mcp.client import Client

from server.main import TOOL_MODULES, build_server

pytestmark = pytest.mark.anyio

RUNS = 50
FORBIDDEN = ("no fault found", "no_fault_found")


def examples():
    found = {}
    for module in TOOL_MODULES:
        for tool, cases in getattr(module, "EXAMPLES", {}).items():
            found.setdefault(tool, []).extend(cases)
    return found


CASES = [(tool, args) for tool, cases in examples().items() for args in cases]
IDS = [f"{tool}-{i}" for i, (tool, _) in enumerate(CASES)]


def answer(result):
    return result.model_dump_json(exclude={"meta"})


async def test_every_tool_ships_examples(settings):
    async with Client(build_server(settings)) as client:
        registered = {t.name for t in (await client.list_tools()).tools}
    assert registered - set(examples()) == set()


@pytest.mark.parametrize(("tool", "args"), CASES, ids=IDS)
async def test_same_answer_every_time(settings, tool, args):
    async with Client(build_server(settings)) as client:
        answers = {answer(await client.call_tool(tool, args)) for _ in range(RUNS)}
    assert len(answers) == 1


@pytest.mark.parametrize(("tool", "args"), CASES, ids=IDS)
async def test_no_outbound_network(settings, monkeypatch, tool, args):
    def refuse(*_, **__):
        raise RuntimeError("outbound network attempted")

    async with Client(build_server(settings)) as client:
        monkeypatch.setattr(socket.socket, "connect", refuse)
        monkeypatch.setattr(socket.socket, "connect_ex", refuse)
        monkeypatch.setattr(socket, "getaddrinfo", refuse)
        result = await client.call_tool(tool, args)
    assert not result.is_error


@pytest.mark.parametrize(("tool", "args"), CASES, ids=IDS)
async def test_never_a_clean_bill(settings, tool, args):
    async with Client(build_server(settings)) as client:
        text = answer(await client.call_tool(tool, args)).lower()
    assert not any(phrase in text for phrase in FORBIDDEN)
