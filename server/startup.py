import logging
from collections.abc import Callable, Sequence
from pathlib import Path

import yaml

from engines.cve.rule_loader import load_rules
from engines.triage.catalog import load as load_catalog
from server.data import data_dir

logger = logging.getLogger(__name__)

SHIPPING_ISSUES = ("bgp-session-down", "interface-degraded", "ospf-neighbor-down")


class StartupError(Exception):
    pass


def load_detector_rules(root: Path) -> None:
    load_rules(root / "rules" / "detectors.toml")


def warm_command_catalog(root: Path) -> None:
    commands = root / "sop" / "vendor_commands.yaml"
    _rows(commands, "vendor_commands", ("capability", "vendor", "command"))
    _rows(root / "sop" / "capabilities.yaml", "capabilities", ("key",))
    load_catalog(root)


def warm_issue_index(root: Path) -> None:
    for key in SHIPPING_ISSUES:
        doc = _yaml(root / "sop" / "issues" / f"{key}.yaml")
        issue = doc.get("issue") if isinstance(doc, dict) else None
        if not isinstance(issue, dict) or issue.get("key") != key:
            raise ValueError(f"issue file for {key} has no matching issue.key")


def import_signals(root: Path) -> None:
    doc = _yaml(root / "sop" / "signals.yaml")
    if not isinstance(doc, dict) or not doc:
        raise ValueError("signals.yaml defines no signals")


def check_corpus_generation(root: Path) -> None:
    from engines.cve.corpus_query import current_generation

    if current_generation() is None:
        raise ValueError("no current corpus generation")


def _yaml(path: Path) -> object:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _rows(path: Path, key: str, required: tuple[str, ...]) -> None:
    doc = _yaml(path)
    rows = doc.get(key) if isinstance(doc, dict) else None
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"{path.name} has no {key}")
    for row in rows:
        if not isinstance(row, dict) or any(not row.get(field) for field in required):
            raise ValueError(f"{path.name} has a {key} row missing {', '.join(required)}")


CHECKS: tuple[tuple[str, Callable[[Path], None]], ...] = (
    ("detector rules", load_detector_rules),
    ("command catalog", warm_command_catalog),
    ("issue index", warm_issue_index),
    ("signals", import_signals),
    ("corpus generation", check_corpus_generation),
)


def run(
    checks: Sequence[tuple[str, Callable[[Path], None]]] | None = None, root: Path | None = None
) -> None:
    root = data_dir() if root is None else root
    for name, check in CHECKS if checks is None else checks:
        try:
            check(root)
        except Exception as exc:
            raise StartupError(f"startup check failed: {name}") from exc
        logger.info("startup check passed: %s", name)
