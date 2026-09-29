import logging
import sys

import uvicorn
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse

from server import startup
from server.app import StratinetServer
from server.settings import Settings, SettingsError
from server.tools import ping

logger = logging.getLogger(__name__)

MAX_REQUEST_BODY_BYTES = 1024 * 1024

TOOL_MODULES = (ping,)


def build_server(settings: Settings) -> StratinetServer:
    mcp = StratinetServer("stratinet", log_level=settings.log_level)
    for module in TOOL_MODULES:
        module.register(mcp)

    @mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
    async def healthz(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    return mcp


def build_app(settings: Settings, mcp: StratinetServer | None = None) -> Starlette:
    return (mcp or build_server(settings)).streamable_http_app(
        stateless_http=True,
        json_response=True,
        max_request_body_size=MAX_REQUEST_BODY_BYTES,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(settings.allowed_hosts),
            allowed_origins=[],
        ),
    )


def main() -> None:
    try:
        settings = Settings.from_env()
    except SettingsError as exc:
        print(f"stratinet-mcp: {exc}", file=sys.stderr)
        sys.exit(1)

    logging.basicConfig(
        level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    try:
        startup.run()
    except startup.StartupError as exc:
        logger.error("%s", exc, exc_info=exc.__cause__)
        sys.exit(1)

    uvicorn.run(
        build_app(settings),
        host="0.0.0.0",
        port=settings.port,
        log_level=settings.log_level.lower(),
        server_header=False,
    )


if __name__ == "__main__":
    main()
