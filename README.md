# Stratinet MCP server

A public, read-only [Model Context Protocol](https://modelcontextprotocol.io) server that answers
questions about network devices: is this software version exposed to a security advisory, which
command checks the same thing on another vendor, and what is wrong with this BGP, OSPF or
interface problem. You bring the facts — vendor, version, pasted command output — and the server
answers from catalogued data and hand-written rules.

## Tools

| Tool | What it does |
|---|---|
| `advisory_exposure` | Says whether an Arista EOS or Fortinet FortiOS version is exposed to a CVE, or lists every CVE that applies to a version. |
| `translate_diagnostic` | Gives the catalogued read-only command for a diagnostic on one or more vendors. |
| `troubleshoot_start` | Gives the ordered read-only checks to run for a symptom on a device. |
| `troubleshoot_analyze` | Reads pasted output of those checks and reports a proven cause, the next commands to run, or that nothing is provable yet. |

Full inputs, outputs and examples: [docs/tools.md](docs/tools.md).

## Two promises

1. **No model decides a result.** Every answer is computed by fixed rules over catalogued data.
   The same input at the same `data_version` gives the same answer, and every answer carries a
   `basis` sentence saying how it was reached.
2. **Never a guessed "not affected".** `advisory_exposure` answers `not_affected` only with a proof
   you can check: the version ranges it compared, or the configuration evidence. When it cannot
   be sure, it says so — `depends_on_configuration`, `cannot_determine` and similar verdicts — and
   tells you what would settle it, such as the command to run or the advisory table to check.
   `troubleshoot_analyze` likewise never reports a healthy device because nothing was found:
   unreadable output is listed in `unread` and never counts as health.

The server never connects to your devices and never returns configuration commands.

## Coverage and its limits

The tools cover different vendors:

| Tool | Vendors |
|---|---|
| `advisory_exposure` | Arista EOS (`arista_eos`), Fortinet FortiOS (`fortinet_fortios`) |
| `troubleshoot_start`, `troubleshoot_analyze` | Arista EOS (`arista_eos`), Cisco IOS (`cisco_ios`), Juniper Junos (`juniper_junos`) |
| `translate_diagnostic` | `arista_eos`, `cisco_ios`, `fortinet_fortianalyzer`, `fortinet_fortimanager`, `fortinet_fortios`, `fortinet_fortiswitch`, `juniper_junos`, `paloalto_panos` |

- **Cisco IOS XE is not claimed.** The tools accept `cisco_ios` only; do not assume IOS XE
  devices behave the same.
- **Advisories.** `advisory_exposure` covers vendor advisories for FortiOS and EOS only, not
  other products from the same vendors. Configuration rules exist for a subset of CVEs; for the
  rest the answer rests on the version ranges and says that configuration was not assessed. The
  advisory data is refreshed regularly, so the same question can get a different answer after an
  update; `data_version` on each answer identifies the data it used, and `checked` in a list
  answer says how many CVEs were examined for that product.
- **Symptoms.** Troubleshooting is built for three symptoms: `bgp-session-down`,
  `ospf-neighbor-down` and `interface-degraded`. A symptom is served only once its procedure has
  been verified; any other symptom is refused with `unsupported_symptom`, whose `supported` list
  names exactly the symptoms served today.
- **Command catalogue.** Many diagnostics are catalogued for one vendor only; for those,
  `translate_diagnostic` answers that no equivalent is catalogued (not that none exists).
- **Hardware validation.** Most catalogued commands have not yet been run on real hardware. Each
  command carries `hardware_verified` so you can tell which have.
- **Partial procedures.** `troubleshoot_start` reports `readable_steps` against `total_steps` when
  some steps of a procedure cannot be read back.

## Get an API key

The hosted server needs an API key. Members create one on the Stratinet community site: sign in,
open your account page and create a key. The key is shown once, so copy it then. You can revoke
a key from the same page; a revoked key stops working within a minute.

Send the key on every request as `Authorization: Bearer <key>`. Keep it secret — anyone with the
key can use your quota.

## Connect

- **Claude Desktop:** install the desktop extension — [docs/quickstart-claude-desktop.md](docs/quickstart-claude-desktop.md).
- **Any other MCP client, or plain HTTP:** connect to the Streamable HTTP endpoint —
  [docs/quickstart-remote.md](docs/quickstart-remote.md).

## Privacy

- A `running_config` you paste into `advisory_exposure` is held in memory for the call, matched
  against the rules and discarded. It is not stored and not logged. Only the matched snippet —
  at most 240 characters — is returned, and only to you, the caller.
- If you would rather not send configuration at all, send `feature_facts` instead (see
  [docs/tools.md](docs/tools.md#advisory_exposure)).
- Server logs never contain your API key; at most its first 8 characters.

## Rate limits

Limits are per API key, counted per minute and per day. Over a limit, the server answers HTTP
`429` with a `Retry-After` header giving the seconds to wait. Keys do not share limits.

## Errors

HTTP-level errors come back with a JSON body `{"error": {"code": ..., "message": ...}}`:

| HTTP | `code` | Meaning |
|---|---|---|
| 401 | `unauthorized` | The `Authorization` header is missing or malformed, or the key is not active. |
| 429 | `rate_limited` | Too many requests for this key. Wait for `Retry-After` seconds. |
| 503 | `unavailable` | The service could not check the key right now. Try again later. |

The server also refuses request bodies over 1 MB (`413`) and requests that carry a browser
`Origin` header (`403`).

A tool call that is rejected returns a tool result with `isError: true` and an `error` object
with `code`, `message` and, where it applies, `field` and `supported`. An error is never a
verdict.

| `code` | Meaning |
|---|---|
| `missing_field` | A required field is missing. |
| `invalid_value` | A field has a value of the wrong type or form. |
| `unknown_field` | The request contains a field this tool does not accept. |
| `input_too_large` | The input is larger than this tool accepts. |
| `unsupported_vendor` | This vendor is not supported by this tool; `supported` lists the vendors it accepts. |
| `unsupported_symptom` | This symptom is not supported by this tool; `supported` lists the symptoms it accepts. |
| `malformed_cve_id` | The CVE id is not in the form `CVE-YYYY-NNNN`. |
| `invalid_feature_fact` | A feature fact does not apply to this feature on this vendor. |
| `internal_error` | The tool could not complete this request, including when it took too long. No detail is returned. |

## Running it yourself / development

Requirements: Python 3.12 and [uv](https://docs.astral.sh/uv/).

```sh
uv sync --frozen
AUTH_MODE=disabled uv run python -m server.main
```

The server listens on `PORT` and serves MCP at `/mcp` and a health check at `/healthz`. On start
it checks its data and exits if anything is missing. The tools need data that is **not** in this
repository: a data bundle (detection rules and the command catalogue) in `DATA_DIR`, and, for
`advisory_exposure`, a PostgreSQL database holding the advisory data, which the server opens
read-only.

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8000` | Port to listen on. |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL`. |
| `ALLOWED_HOSTS` | `localhost:*,127.0.0.1:*` | Comma-separated `Host` header values the server accepts. |
| `DATA_DIR` | `data` | Directory holding the data bundle. |
| `AUTH_MODE` | `api_key` | `api_key` checks keys and limits; `disabled` turns both off, for local use only. |
| `API_KEYS_TABLE`, `USAGE_TABLE` | — | With `api_key`: the DynamoDB tables holding key status and call counts. |
| `AWS_REGION` | — | With `api_key`: the region of those tables (`AWS_DEFAULT_REGION` also works). |
| `RATE_LIMIT_PER_MINUTE` | `60` | Calls per key per minute. |
| `RATE_LIMIT_PER_DAY` | `5000` | Calls per key per day; must be at least the per-minute limit. |
| `API_KEY_CACHE_SECONDS` | `60` | How long a key check is cached, `0` to `60`. |
| `TOOL_TIMEOUT_SECONDS` | `30` | Time limit for one tool call, up to `600`. |
| `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD` | — | Standard PostgreSQL connection variables for the advisory database. |

[example.env](example.env) has the local defaults. The `Dockerfile` builds a runtime image
(`--target runtime`, data expected in `/bundle`) and a test image (`--target test`).

Checks, as run in CI:

```sh
uv run --no-sync ruff check .
uv run --no-sync ruff format --check .
uv run --no-sync pytest
uv run --no-sync python packaging/check.py
uv run --no-sync python scripts/gen_tool_docs.py --check
```

- `packaging/check.py` validates the registry listing (`packaging/server.json`) and the desktop
  extension (`packaging/mcpb/`) against the server's registered tools. After changing a tool's
  name or description, run `packaging/check.py --write-tools`. To build release files, run
  `packaging/check.py --release --mcp-url https://<your-endpoint>/mcp --privacy-url <url>`,
  which writes `server.json` and the `.mcpb` bundle to `dist/packaging/`.
- `scripts/gen_tool_docs.py` regenerates the input tables in [docs/tools.md](docs/tools.md) from
  each tool's schema; `--check` fails if they are out of date.
