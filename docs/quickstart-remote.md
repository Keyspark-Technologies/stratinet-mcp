# Quickstart: remote MCP clients

Stratinet is a remote MCP server using the Streamable HTTP transport. Any MCP client that can
connect to a remote server and send a request header can use it.

| | |
|---|---|
| Endpoint | `https://<your-endpoint>/mcp` |
| Transport | Streamable HTTP; the server is stateless and answers with plain JSON |
| Authentication | `Authorization: Bearer <your API key>` on every request |

Get a key first: see [Get an API key](../README.md#get-an-api-key).

## Claude (custom connector)

Where your Claude plan lets you add a custom connector with request headers, add one with:

- **URL:** `https://<your-endpoint>/mcp`
- **Header:** `Authorization` = `Bearer <your API key>`

If your Claude client cannot send a custom header, use the
[Claude Desktop extension](quickstart-claude-desktop.md) instead; it adds the header for you.

## Claude Code

```sh
claude mcp add --transport http stratinet https://<your-endpoint>/mcp \
  --header "Authorization: Bearer <your API key>"
```

## Other clients

Most clients take a JSON configuration naming the URL and headers. The exact keys differ between
clients; check your client's documentation. A typical entry:

```json
{
  "mcpServers": {
    "stratinet": {
      "type": "http",
      "url": "https://<your-endpoint>/mcp",
      "headers": { "Authorization": "Bearer <your API key>" }
    }
  }
}
```

Keep the key out of files you share or commit; many clients can read it from an environment
variable instead.

## Raw HTTP

The examples below use `curl`. Every request is a JSON-RPC message sent by `POST` to the
endpoint. Set the endpoint and your key first:

```sh
ENDPOINT='https://<your-endpoint>/mcp'
KEY='<your API key>'
```

### 1. initialize

```sh
curl -sS "$ENDPOINT" \
  -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl","version":"1.0"}}}'
```

The result names the protocol version the server agreed to in `result.protocolVersion`. Send it
as the `MCP-Protocol-Version` header on the requests that follow. The server is stateless, so
there is no session id to carry.

### 2. tools/list

```sh
curl -sS "$ENDPOINT" \
  -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-11-25' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
```

`result.tools` lists the four tools with their `name`, `description` and `inputSchema`.

### 3. tools/call

```sh
curl -sS "$ENDPOINT" \
  -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-11-25' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"translate_diagnostic","arguments":{"capability":"check-bgp-summary","target_vendor":"juniper_junos"}}}'
```

The answer is in `result.structuredContent`, and the same JSON as text in
`result.content[0].text`. `result.isError` is `true` when the input was rejected; the body then
holds an `error` object instead of an answer:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [{"type": "text", "text": "{\"error\": {...}}"}],
    "structuredContent": {
      "error": {
        "code": "unsupported_vendor",
        "message": "This vendor is not supported by this tool.",
        "field": "target_vendor",
        "supported": ["arista_eos", "cisco_ios", "..."]
      }
    },
    "isError": true
  }
}
```

See [tools.md](tools.md) for every tool's inputs and answers.

## HTTP errors

A missing or inactive key gets `401`, and too many calls get `429` with a `Retry-After` header.
The full list is in the [README](../README.md#errors).
