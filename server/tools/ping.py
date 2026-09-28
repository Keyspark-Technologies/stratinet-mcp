from mcp.server.mcpserver import MCPServer


def register(mcp: MCPServer) -> None:
    @mcp.tool(description="Returns 'pong'. Confirms the server is reachable.")
    def ping() -> str:
        return "pong"
