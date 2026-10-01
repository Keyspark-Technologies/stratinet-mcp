from dataclasses import dataclass
from functools import lru_cache
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


@dataclass(frozen=True)
class VendorCommand:
    command: str
    params: tuple[str, ...]


def command_for(capability: str, vendor: str) -> VendorCommand | None:
    return _command_index(_sop_dir()).get((capability, vendor))


@lru_cache(maxsize=4)
def _command_index(sop_dir: Path) -> dict[tuple[str, str], VendorCommand]:
    index: dict[tuple[str, str], VendorCommand] = {}
    for row in load_vendor_commands():
        key = (row.get("capability"), row.get("vendor"))
        if key not in index and row.get("command"):
            index[key] = VendorCommand(row["command"], tuple(row.get("params") or ()))
    return index
