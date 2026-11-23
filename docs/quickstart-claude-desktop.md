# Quickstart: Claude Desktop

The Stratinet desktop extension adds the four tools to Claude Desktop on macOS and Windows. It is
a small local bridge: it forwards each request over HTTPS to the hosted Stratinet server with your
API key. Whatever you give the tools, including pasted configuration or command output, is sent to
that server (see [Privacy](../README.md#privacy)).

## What you need

- Claude Desktop on macOS or Windows, with extensions enabled.
- A Stratinet API key (see [Get an API key](../README.md#get-an-api-key)).

## Install

1. Download the extension file, `stratinet-mcp-<version>.mcpb`, from the latest release of this
   repository.
2. Open it with Claude Desktop — double-click the file, or drag it into the Claude Desktop window,
   or use **Settings → Extensions** and install it from there.
3. Review the extension and choose **Install**.

## Enter your API key

1. In **Settings → Extensions**, open **Stratinet** and its settings.
2. Paste your key into **API key**. Claude Desktop stores it as a sensitive value and the extension
   sends it only to the server URL.
3. Leave **Server URL** at its default unless you were given another endpoint. It must be an
   `https://` URL.
4. Make sure the extension is enabled.

## Try it

Start a new chat and ask, for example:

- "Use Stratinet to check whether FortiOS 7.0.3 is exposed to CVE-2024-21762."
- "What is the Junos command for check-bgp-summary?"
- "My OSPF neighbour on a Cisco IOS router is down. What should I check first?"

Claude asks for permission the first time it calls a tool. The answers come back as structured
results; see [tools.md](tools.md) for what each field means.

## If something goes wrong

The extension reports problems as tool errors in the chat:

| Message | What to do |
|---|---|
| Set your Stratinet API key in the extension settings. | The API key is empty. Enter it as above. |
| The server URL must be an https URL. | Fix **Server URL**, or reset it to the default. |
| A valid API key is required. | The key is wrong, revoked or mistyped. Create a new one on your account page. |
| Too many requests for this API key. Try again later. | You reached a rate limit for this key. Wait and retry. |
| The Stratinet server could not be reached. | Check your network connection. A request also gives up after 60 seconds. |
