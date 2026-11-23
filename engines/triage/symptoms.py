import functools
from collections.abc import Iterable
from pathlib import Path

import yaml

from common.validate import ToolInputError
from server.data import data_dir

ISSUE_KEYS = ("bgp-session-down", "interface-degraded", "ospf-neighbor-down")
ALIAS_FILE = "symptom_aliases.yaml"
TABLE_KEY = "symptom_aliases"


class AliasTableError(ValueError):
    pass


def normalise(text: str) -> str:
    return " ".join(text.lower().split())


def _duplicate_key(node: yaml.Node) -> str | None:
    if isinstance(node, yaml.MappingNode):
        seen = set()
        for key, value in node.value:
            name = key.value if isinstance(key, yaml.ScalarNode) else None
            if name is not None and name in seen:
                return name
            seen.add(name)
            found = _duplicate_key(value)
            if found is not None:
                return found
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            found = _duplicate_key(item)
            if found is not None:
                return found
    return None


def _document(path: Path) -> object:
    text = path.read_text(encoding="utf-8")
    try:
        node = yaml.compose(text, Loader=yaml.SafeLoader)
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise AliasTableError(f"{ALIAS_FILE} is not valid YAML") from exc
    if node is not None and (name := _duplicate_key(node)) is not None:
        raise AliasTableError(f"{ALIAS_FILE} repeats the key {name!r}")
    return doc


def load(root: Path) -> dict[str, str]:
    path = Path(root) / "sop" / ALIAS_FILE
    if not path.is_file():
        return {}
    doc = _document(path)
    if not isinstance(doc, dict) or list(doc) != [TABLE_KEY]:
        raise AliasTableError(f"{ALIAS_FILE} must hold exactly one {TABLE_KEY} mapping")
    table = doc[TABLE_KEY]
    if not isinstance(table, dict):
        raise AliasTableError(f"{TABLE_KEY} must map issue keys to lists of phrases")
    aliases: dict[str, str] = {}
    for key in sorted(table, key=str):
        if key not in ISSUE_KEYS:
            raise AliasTableError(f"{TABLE_KEY} names {key!r}, which is not a supported issue key")
        phrases = table[key]
        if not isinstance(phrases, list):
            raise AliasTableError(f"the aliases for {key} must be a list of phrases")
        for phrase in phrases:
            if not isinstance(phrase, str) or not phrase.strip():
                raise AliasTableError(f"an alias for {key} is not text")
            spoken = normalise(phrase)
            if spoken in ISSUE_KEYS and spoken != key:
                raise AliasTableError(f"the alias {spoken!r} under {key} is another issue key")
            if aliases.get(spoken, key) != key:
                raise AliasTableError(
                    f"the alias {spoken!r} appears under both {aliases[spoken]} and {key}"
                )
            aliases[spoken] = key
    return aliases


@functools.lru_cache(maxsize=4)
def _cached(root: Path) -> dict[str, str]:
    return load(root)


def aliases() -> dict[str, str]:
    return dict(_cached(data_dir().resolve()))


def resolve(value: str, supported: Iterable[str]) -> str:
    allowed = sorted(supported)
    spoken = normalise(value)
    key = spoken if spoken in ISSUE_KEYS else aliases().get(spoken)
    if key not in allowed:
        raise ToolInputError("unsupported_symptom", supported=allowed, field="symptom")
    return key
