import socket
import threading
import time
from pathlib import Path

import pytest
import uvicorn

from server.main import build_app
from server.settings import Settings

FIXTURE_DATA = Path(__file__).parent / "fixtures" / "bundle"


def clear_engine_caches():
    from engines.triage import catalog, select, signals, triage

    for cached in (
        catalog._cached,
        select._index,
        signals.load_signals,
        triage._clause_order,
        triage._compares_both_ends,
    ):
        cached.cache_clear()


@pytest.fixture(autouse=True)
def fixture_data_dir(monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(FIXTURE_DATA))
    clear_engine_caches()
    yield FIXTURE_DATA
    clear_engine_caches()


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def settings() -> Settings:
    return Settings(port=0, log_level="INFO", allowed_hosts=("localhost:*", "127.0.0.1:*"))


@pytest.fixture
def live_server(settings):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(build_app(settings), host="127.0.0.1", port=port, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("test server did not start")
        time.sleep(0.05)
    yield f"http://localhost:{port}"
    server.should_exit = True
    thread.join(timeout=10)
