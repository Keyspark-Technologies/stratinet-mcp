from pathlib import Path

import yaml

from server.data import data_dir


def _sop_dir() -> Path:
    return data_dir() / "sop"


def _read(name: str) -> dict:
    return yaml.safe_load((_sop_dir() / name).read_text(encoding="utf-8")) or {}


def load_capabilities() -> list[dict]:
    return _read("capabilities.yaml").get("capabilities", [])


def load_vendor_commands() -> list[dict]:
    return _read("vendor_commands.yaml").get("vendor_commands", [])


def load_issues() -> list[dict]:
    out = []
    for path in sorted((_sop_dir() / "issues").glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if doc and doc.get("issue"):
            out.append(doc)
    return out
