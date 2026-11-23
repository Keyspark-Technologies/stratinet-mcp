"use strict";

const readline = require("node:readline");

const TIMEOUT_MS = 60000;
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
const NO_URL = "The server URL must be an https URL.";
const NO_KEY = "Set your Stratinet API key in the extension settings.";
const UNREACHABLE = "The Stratinet server could not be reached.";
const UNREADABLE = "The Stratinet server sent a reply that could not be read.";

const apiKey = (process.env.STRATINET_API_KEY || "").trim();
const endpoint = parseEndpoint(process.env.STRATINET_MCP_URL || "");
const session = { protocolVersion: null, id: null };
let pending = 0;
let closed = false;

function parseEndpoint(raw) {
  let url;
  try {
    url = new URL(raw.trim());
  } catch {
    return null;
  }
  if (url.protocol === "https:") return url;
  if (url.protocol === "http:" && LOCAL_HOSTS.has(url.hostname)) return url;
  return null;
}

function write(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function fail(id, message) {
  if (id === undefined || id === null) return;
  write({ jsonrpc: "2.0", id, error: { code: -32000, message } });
}

function events(text) {
  const messages = [];
  for (const block of text.split(/\r?\n\r?\n/)) {
    const data = block
      .split(/\r?\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).replace(/^ /, ""));
    if (data.length) messages.push(data.join("\n"));
  }
  return messages;
}

function httpMessage(status, text) {
  try {
    const message = JSON.parse(text).error.message;
    if (typeof message === "string" && message) return message;
  } catch {}
  return `The Stratinet server answered HTTP ${status}.`;
}

function headers() {
  const result = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    authorization: `Bearer ${apiKey}`,
  };
  if (session.protocolVersion) result["mcp-protocol-version"] = session.protocolVersion;
  if (session.id) result["mcp-session-id"] = session.id;
  return result;
}

async function forward(message) {
  const id = message.id;
  if (!endpoint) return fail(id, NO_URL);
  if (!apiKey) return fail(id, NO_KEY);
  let response;
  let text;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify(message),
      redirect: "error",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    text = await response.text();
  } catch {
    return fail(id, UNREACHABLE);
  }
  if (response.status === 202) return;
  if (!response.ok) return fail(id, httpMessage(response.status, text));
  if (message.method === "initialize") session.id = response.headers.get("mcp-session-id");
  const type = response.headers.get("content-type") || "";
  const replies = type.includes("text/event-stream") ? events(text) : [text];
  for (const reply of replies) {
    let parsed;
    try {
      parsed = JSON.parse(reply);
    } catch {
      fail(id, UNREADABLE);
      continue;
    }
    if (message.method === "initialize" && parsed.result) {
      session.protocolVersion = parsed.result.protocolVersion || null;
    }
    write(parsed);
  }
}

function finish() {
  if (closed && pending === 0) process.exit(0);
}

const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

input.on("line", (line) => {
  if (!line.trim()) return;
  let message;
  try {
    message = JSON.parse(line);
  } catch {
    write({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
    return;
  }
  pending += 1;
  forward(message)
    .catch(() => fail(message.id, UNREACHABLE))
    .finally(() => {
      pending -= 1;
      finish();
    });
});

input.on("close", () => {
  closed = true;
  finish();
});
