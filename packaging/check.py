import argparse
import asyncio
import json
import re
import sys
import tomllib
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PACKAGING = ROOT / "packaging"
SERVER_JSON = PACKAGING / "server.json"
BUNDLE = PACKAGING / "mcpb"
MANIFEST = BUNDLE / "manifest.json"

REGISTRY_SCHEMA = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
REGISTRY_NAME = re.compile(r"[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+")
MANIFEST_VERSION = "0.3"
MANIFEST_KEYS = frozenset(
    {
        "$schema",
        "manifest_version",
        "name",
        "display_name",
        "version",
        "description",
        "long_description",
        "author",
        "repository",
        "homepage",
        "documentation",
        "support",
        "icon",
        "icons",
        "screenshots",
        "localization",
        "server",
        "tools",
        "tools_generated",
        "prompts",
        "prompts_generated",
        "keywords",
        "license",
        "privacy_policies",
        "compatibility",
        "user_config",
        "_meta",
    }
)
MCP_URL_PLACEHOLDER = "https://stratinet-mcp.invalid/mcp"
PRIVACY_URL_PLACEHOLDER = "https://stratinet-mcp-privacy.invalid/"
PLACEHOLDER_MARK = ".invalid"
HTTPS_URL = re.compile(r"https://[^\s/?#]+\.[^\s/?#]+(/[^\s]*)?")
ENTRY_POINT = "server/index.js"
BUNDLE_FILES = ("manifest.json", ENTRY_POINT)


class PackagingError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PackagingError(message)


def project_version() -> str:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)["project"]["version"]


def registered_tools() -> list[dict[str, str]]:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from server.main import build_server
    from server.settings import Settings

    settings = Settings(port=8000, log_level="WARNING", allowed_hosts=("localhost",), auth=None)
    tools = asyncio.run(build_server(settings).list_tools())
    return [{"name": t.name, "description": t.description or ""} for t in tools]


def load(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PackagingError(f"{path.name}: not valid JSON ({exc})") from exc
    require(isinstance(data, dict), f"{path.name}: top level must be an object")
    return data


def https_url(value: Any) -> bool:
    return isinstance(value, str) and HTTPS_URL.fullmatch(value) is not None


def check_server_json(data: dict[str, Any], version: str) -> None:
    require(data.get("$schema") == REGISTRY_SCHEMA, "server.json: $schema is not the pinned one")
    require(
        isinstance(data.get("name"), str) and REGISTRY_NAME.fullmatch(data["name"]) is not None,
        "server.json: name must be namespace/name",
    )
    description = data.get("description")
    require(
        isinstance(description, str) and 1 <= len(description) <= 100,
        "server.json: description must be 1 to 100 characters",
    )
    require(data.get("version") == version, f"server.json: version must be {version}")
    require(https_url(data.get("websiteUrl")), "server.json: websiteUrl must be an https URL")
    repository = data.get("repository") or {}
    require(
        https_url(repository.get("url")) and repository.get("source") == "github",
        "server.json: repository needs an https url and source github",
    )
    require("packages" not in data, "server.json: this server is listed as remote only")
    remotes = data.get("remotes")
    require(isinstance(remotes, list) and len(remotes) == 1, "server.json: needs one remote")
    remote = remotes[0]
    require(remote.get("type") == "streamable-http", "server.json: remote must be streamable-http")
    require(https_url(remote.get("url")), "server.json: remote url must be an https URL")
    require(remote["url"].endswith("/mcp"), "server.json: remote url must end with /mcp")
    headers = remote.get("headers")
    require(isinstance(headers, list) and len(headers) == 1, "server.json: needs one header")
    header = headers[0]
    require(header.get("name") == "Authorization", "server.json: header must be Authorization")
    require(
        header.get("isRequired") is True and header.get("isSecret") is True,
        "server.json: Authorization must be required and secret",
    )
    require(
        header.get("value") == "Bearer {api_key}",
        "server.json: Authorization value must be 'Bearer {api_key}'",
    )
    api_key = (header.get("variables") or {}).get("api_key") or {}
    require(
        api_key.get("isRequired") is True and api_key.get("isSecret") is True,
        "server.json: api_key variable must be required and secret",
    )


def check_manifest(data: dict[str, Any], version: str, tools: list[dict[str, str]]) -> None:
    unknown = sorted(set(data) - MANIFEST_KEYS)
    require(not unknown, f"manifest.json: unknown fields {unknown}")
    require(
        data.get("manifest_version") == MANIFEST_VERSION,
        f"manifest.json: manifest_version must be {MANIFEST_VERSION}",
    )
    for key in ("name", "display_name", "description", "long_description"):
        require(
            isinstance(data.get(key), str) and data[key].strip(), f"manifest.json: {key} missing"
        )
    require(data.get("version") == version, f"manifest.json: version must be {version}")
    author = data.get("author") or {}
    require(isinstance(author.get("name"), str), "manifest.json: author.name missing")
    server = data.get("server") or {}
    require(server.get("type") == "node", "manifest.json: server.type must be node")
    require(
        server.get("entry_point") == ENTRY_POINT,
        f"manifest.json: entry_point must be {ENTRY_POINT}",
    )
    config = server.get("mcp_config") or {}
    require(config.get("command") == "node", "manifest.json: mcp_config.command must be node")
    require(
        config.get("args") == [f"${{__dirname}}/{ENTRY_POINT}"],
        "manifest.json: mcp_config.args must run the entry point",
    )
    require(
        config.get("env")
        == {
            "STRATINET_MCP_URL": "${user_config.server_url}",
            "STRATINET_API_KEY": "${user_config.api_key}",
        },
        "manifest.json: mcp_config.env must pass server_url and api_key",
    )
    user_config = data.get("user_config") or {}
    api_key = user_config.get("api_key") or {}
    require(
        api_key.get("type") == "string"
        and api_key.get("required") is True
        and api_key.get("sensitive") is True,
        "manifest.json: api_key must be a required sensitive string",
    )
    server_url = user_config.get("server_url") or {}
    require(
        server_url.get("type") == "string" and https_url(server_url.get("default")),
        "manifest.json: server_url needs an https default",
    )
    policies = data.get("privacy_policies")
    require(
        isinstance(policies, list) and policies and all(https_url(p) for p in policies),
        "manifest.json: privacy_policies must list https URLs",
    )
    require(data.get("tools_generated") is False, "manifest.json: tools_generated must be false")
    require(
        data.get("tools") == tools,
        "manifest.json: tools differ from the server's registered tools; "
        "run packaging/check.py --write-tools",
    )


def check_shared(server_json: dict[str, Any], manifest: dict[str, Any]) -> None:
    require(
        server_json["description"] == manifest["description"],
        "server.json and manifest.json descriptions differ",
    )
    require(
        server_json["remotes"][0]["url"] == manifest["user_config"]["server_url"]["default"],
        "server.json remote url and manifest.json server_url default differ",
    )


def check_no_placeholder(texts: dict[str, str]) -> None:
    for name, text in texts.items():
        require(PLACEHOLDER_MARK not in text, f"{name}: a placeholder URL is left")


def check_all(server_json: dict[str, Any], manifest: dict[str, Any]) -> None:
    version = project_version()
    check_server_json(server_json, version)
    check_manifest(manifest, version, registered_tools())
    check_shared(server_json, manifest)
    require((BUNDLE / ENTRY_POINT).is_file(), f"mcpb/{ENTRY_POINT} is missing")


def substitute(text: str, mcp_url: str, privacy_url: str) -> str:
    return text.replace(MCP_URL_PLACEHOLDER, mcp_url).replace(PRIVACY_URL_PLACEHOLDER, privacy_url)


def release(mcp_url: str, privacy_url: str, out: Path) -> list[Path]:
    require(https_url(mcp_url) and mcp_url.endswith("/mcp"), "--mcp-url must be https and end /mcp")
    require(https_url(privacy_url), "--privacy-url must be an https URL")
    check_no_placeholder({"--mcp-url": mcp_url, "--privacy-url": privacy_url})
    texts = {
        "server.json": substitute(SERVER_JSON.read_text(encoding="utf-8"), mcp_url, privacy_url),
        "manifest.json": substitute(MANIFEST.read_text(encoding="utf-8"), mcp_url, privacy_url),
        ENTRY_POINT: (BUNDLE / ENTRY_POINT).read_text(encoding="utf-8"),
    }
    check_no_placeholder(texts)
    server_json = json.loads(texts["server.json"])
    manifest = json.loads(texts["manifest.json"])
    check_all(server_json, manifest)
    require(server_json["remotes"][0]["url"] == mcp_url, "server.json url was not substituted")
    out.mkdir(parents=True, exist_ok=True)
    registry = out / "server.json"
    registry.write_text(texts["server.json"], encoding="utf-8")
    bundle = out / f"{manifest['name']}-{manifest['version']}.mcpb"
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in BUNDLE_FILES:
            archive.writestr(name, texts[name])
    return [registry, bundle]


def write_tools() -> None:
    manifest = load(MANIFEST)
    manifest["tools"] = registered_tools()
    MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="packaging/check.py")
    parser.add_argument("--write-tools", action="store_true")
    parser.add_argument("--release", action="store_true")
    parser.add_argument("--mcp-url")
    parser.add_argument("--privacy-url")
    parser.add_argument("--out", type=Path, default=ROOT / "dist" / "packaging")
    args = parser.parse_args(argv)
    try:
        if args.write_tools:
            write_tools()
        check_all(load(SERVER_JSON), load(MANIFEST))
        if args.release:
            require(
                bool(args.mcp_url and args.privacy_url),
                "--release needs --mcp-url and --privacy-url",
            )
            for path in release(args.mcp_url, args.privacy_url, args.out):
                print(f"wrote {path}")
    except PackagingError as exc:
        print(f"packaging check failed: {exc}", file=sys.stderr)
        return 1
    print("packaging check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
