import argparse
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "tools.md"
BLOCK = re.compile(
    r"(<!-- BEGIN GENERATED: (?P<name>[a-z_]+) -->\n).*?(\n<!-- END GENERATED: (?P=name) -->)",
    re.DOTALL,
)
HEADER = (
    "| Field | Type | Required | Notes |",
    "|---|---|---|---|",
)


def tool_modules() -> list[Any]:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from server.main import TOOL_MODULES

    return list(TOOL_MODULES)


def cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def code_list(values: list[Any]) -> str:
    return ", ".join(f"`{v}`" for v in values)


def kind(schema: dict[str, Any]) -> str:
    if "oneOf" in schema:
        return " or ".join(kind(option) for option in schema["oneOf"])
    if schema.get("type") == "array":
        return f"list of {kind(schema.get('items') or {})}s"
    if schema.get("type") == "object" and isinstance(schema.get("additionalProperties"), dict):
        return f"object of {kind(schema['additionalProperties'])}s"
    return schema.get("type", "value")


def enum(schema: dict[str, Any]) -> list[Any]:
    if "enum" in schema:
        return list(schema["enum"])
    for inner in [
        *(schema.get("oneOf") or []),
        schema.get("items"),
        schema.get("additionalProperties"),
    ]:
        if isinstance(inner, dict) and enum(inner):
            return enum(inner)
    return []


def span(low: Any, high: Any, unit: str) -> str | None:
    if low is not None and high is not None:
        return f"{low} to {high} {unit}"
    if high is not None:
        return f"at most {high} {unit}"
    if low is not None:
        return f"at least {low} {unit}"
    return None


def limits(schema: dict[str, Any]) -> list[str]:
    found = [
        span(schema.get("minLength"), schema.get("maxLength"), "characters"),
        span(schema.get("minItems"), schema.get("maxItems"), "items"),
        span(None, schema.get("maxProperties"), "keys"),
    ]
    out = [text for text in found if text]
    if schema.get("uniqueItems"):
        out.append("no repeats")
    if "default" in schema:
        out.append(f"default `{str(schema['default']).lower()}`")
    if schema.get("type") == "object" and schema.get("additionalProperties") is False:
        out.append("no other keys")
    return out


def notes(schema: dict[str, Any]) -> str:
    parts = [schema["description"].rstrip(".")] if schema.get("description") else []
    values = enum(schema)
    if values:
        label = "values" if schema.get("type") == "object" else "one of"
        parts.append(f"{label}: {code_list(values)}")
    for option in schema.get("oneOf") or []:
        parts.extend(limits(option))
    parts.extend(limits(schema))
    return "; ".join(parts) + "." if parts else ""


def rows(schema: dict[str, Any], prefix: str = "") -> list[str]:
    out = []
    required = set(schema.get("required") or ())
    for name, prop in (schema.get("properties") or {}).items():
        field = f"{prefix}{name}"
        needed = "yes" if name in required else "no"
        out.append(f"| `{field}` | {cell(kind(prop))} | {needed} | {cell(notes(prop))} |")
        if prop.get("type") == "object" and prop.get("properties"):
            out.extend(rows(prop, f"{field}."))
        items = prop.get("items") or {}
        if prop.get("type") == "array" and items.get("properties"):
            out.extend(rows(items, f"{field}[]."))
    return out


def render(module: Any) -> str:
    lines = [f"> {module.DESCRIPTION}", "", *HEADER, *rows(module.SCHEMA), ""]
    return "\n".join(lines)


def generate(text: str, modules: list[Any]) -> str:
    blocks = {module.NAME: render(module) for module in modules}
    found = [m.group("name") for m in BLOCK.finditer(text)]
    missing = sorted(set(blocks) - set(found))
    unknown = sorted(set(found) - set(blocks))
    if missing or unknown or len(found) != len(set(found)):
        raise ValueError(
            f"generated markers do not match the tools: missing {missing}, unknown {unknown}"
        )
    return BLOCK.sub(lambda m: m.group(1) + blocks[m.group("name")] + m.group(3), text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scripts/gen_tool_docs.py")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    current = DOC.read_text(encoding="utf-8")
    try:
        updated = generate(current, tool_modules())
    except ValueError as exc:
        print(f"tool docs: {exc}", file=sys.stderr)
        return 1
    if args.check:
        if updated != current:
            print(
                "tool docs are out of date; run: uv run python scripts/gen_tool_docs.py",
                file=sys.stderr,
            )
            return 1
        print("tool docs are up to date")
        return 0
    if updated != current:
        DOC.write_text(updated, encoding="utf-8")
        print(f"updated {DOC.relative_to(ROOT)}")
    else:
        print("tool docs are up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
