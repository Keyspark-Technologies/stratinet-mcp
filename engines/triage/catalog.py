import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from server.data import data_dir

from .triage_readonly import _is_read_only

NOT_CATALOGUED = "no command catalogued for this capability on the requested vendor"
NOT_A_CHECK = "the capability is not a read-only check"
NO_KIND = "the capability has no kind in the catalog, so it is refused"
NOT_READ_ONLY = "a catalogued command for this capability is not read-only"
MAX_SUGGESTIONS = 5

_CANONICAL = {
    "sh": "show",
    "sho": "show",
    "int": "interface",
    "inte": "interface",
    "inter": "interface",
    "interf": "interface",
    "interfaces": "interface",
    "nei": "neighbor",
    "neig": "neighbor",
    "neigh": "neighbor",
    "neighbors": "neighbor",
    "neighbour": "neighbor",
    "neighbours": "neighbor",
    "bri": "brief",
    "sum": "summary",
    "summ": "summary",
    "det": "detail",
    "ver": "version",
    "run": "running-config",
    "log": "logging",
    "ext": "extensive",
    "ter": "terse",
    "desc": "description",
    "trans": "transceiver",
}
_PLACEHOLDER = re.compile(r"\{[^}]*\}")
_WILDCARD = "{}"


@dataclass(frozen=True)
class Command:
    vendor: str
    command: str
    params: tuple[str, ...]
    hardware_verified: bool


def normalise(command: str) -> str:
    text = _PLACEHOLDER.sub(f" {_WILDCARD} ", command.lower())
    return " ".join(_CANONICAL.get(word, word) for word in text.split())


class Catalog:
    def __init__(self, capabilities: dict, commands: dict, signalled: frozenset[str]):
        self.capabilities = capabilities
        self.commands = commands
        self._signalled = signalled
        self._by_capability: dict[str, dict[str, Command]] = {}
        exact: dict[tuple[str, str], set[str]] = {}
        templates: dict[str, list[tuple[tuple[str, ...], str]]] = {}
        for (capability, vendor), command in sorted(commands.items()):
            self._by_capability.setdefault(capability, {})[vendor] = command
            form = normalise(command.command)
            if _WILDCARD in form.split():
                templates.setdefault(vendor, []).append((tuple(form.split()), capability))
            else:
                exact.setdefault((vendor, form), set()).add(capability)
        self._exact = {k: tuple(sorted(v, key=self._rank)) for k, v in exact.items()}
        self._templates = templates

    def _rank(self, capability: str) -> tuple[bool, str]:
        return (capability not in self._signalled, capability)

    def command_for(self, capability: str, vendor: str) -> Command | None:
        return self.commands.get((capability, vendor))

    def capabilities_for(self, vendor: str, command: str) -> tuple[str, ...]:
        form = normalise(command)
        found = set(self._exact.get((vendor, form), ()))
        words = form.split()
        for pattern, capability in self._templates.get(vendor, ()):
            if len(pattern) == len(words) and all(
                p == _WILDCARD or p == w for p, w in zip(pattern, words, strict=True)
            ):
                found.add(capability)
        return tuple(sorted(found, key=self._rank))

    def did_you_mean(self, text: str) -> list[str]:
        query = " ".join(text.lower().split())
        if not query:
            return []
        as_key = query.replace(" ", "-")
        hits = [
            key
            for key in sorted(self._by_capability)
            if self._is_check(key)
            and (
                key.startswith(as_key)
                or as_key in key
                or query in (self.capabilities.get(key, {}).get("description") or "").lower()
            )
        ]
        return hits[:MAX_SUGGESTIONS]

    def _is_check(self, capability: str) -> bool:
        return (self.capabilities.get(capability) or {}).get("kind") == "check"

    def translate(self, capability: str, vendors: list[str]) -> dict:
        spec = self.capabilities.get(capability)
        rows = self._by_capability.get(capability, {})
        if spec is None and not rows:
            return {"status": "unknown_capability", "did_you_mean": self.did_you_mean(capability)}
        if spec is None or not spec.get("kind"):
            return _refused(capability, NO_KIND)
        if spec.get("kind") != "check":
            return _refused(capability, NOT_A_CHECK)
        if any(not _is_read_only(c.command) for c in rows.values()):
            return _refused(capability, NOT_READ_ONLY)
        requested = sorted(set(vendors))
        found = [rows[v] for v in requested if v in rows]
        if not found:
            return {
                "status": "no_equivalent",
                "capability": capability,
                "requested_vendor": requested[0] if len(requested) == 1 else requested,
                "available_for": sorted(rows),
                "reason": NOT_CATALOGUED,
            }
        return {
            "status": "translated",
            "capability": capability,
            "description": spec.get("description") or "",
            "kind": "check",
            "commands": [
                {
                    "vendor": c.vendor,
                    "command": c.command,
                    "params": list(c.params),
                    "hardware_verified": c.hardware_verified,
                }
                for c in found
            ],
            "coverage": {"vendors_available": len(found), "vendors_requested": len(requested)},
        }


def _refused(capability: str, reason: str) -> dict:
    return {"status": "refused_not_read_only", "capability": capability, "reason": reason}


def _yaml(path: Path) -> object:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _verified_commands(sop: Path) -> frozenset[tuple[str, str]]:
    path = sop / "hardware_verified.yaml"
    if not path.is_file():
        return frozenset()
    rows = _yaml(path) or []
    if isinstance(rows, dict):
        rows = rows.get("hardware_verified") or []
    return frozenset(
        (row["vendor"], row["command"])
        for row in rows
        if isinstance(row, dict)
        and row.get("device_accepted") is True
        and isinstance(row.get("vendor"), str)
        and isinstance(row.get("command"), str)
    )


def load(root: Path) -> Catalog:
    sop = Path(root) / "sop"
    capabilities = {
        row["key"]: row
        for row in (_yaml(sop / "capabilities.yaml") or {}).get("capabilities") or []
        if isinstance(row, dict) and row.get("key")
    }
    verified = _verified_commands(sop)
    commands: dict[tuple[str, str], Command] = {}
    for row in (_yaml(sop / "vendor_commands.yaml") or {}).get("vendor_commands") or []:
        key = (row.get("capability"), row.get("vendor"))
        if not all(key) or not row.get("command") or key in commands:
            continue
        commands[key] = Command(
            vendor=row["vendor"],
            command=row["command"],
            params=tuple(row.get("params") or ()),
            hardware_verified=(row["vendor"], row["command"]) in verified,
        )
    if not commands:
        raise ValueError("the command catalog is empty")
    signals_path = sop / "signals.yaml"
    signalled = (
        frozenset(k for k, v in (_yaml(signals_path) or {}).items() if isinstance(v, dict))
        if signals_path.is_file()
        else frozenset()
    )
    return Catalog(capabilities, commands, signalled)


@lru_cache(maxsize=4)
def _cached(root: Path) -> Catalog:
    return load(root)


def current() -> Catalog:
    return _cached(data_dir().resolve())


def command_for(capability: str, vendor: str) -> Command | None:
    return current().command_for(capability, vendor)
