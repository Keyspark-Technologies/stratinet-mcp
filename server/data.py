import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path


def data_dir() -> Path:
    return Path(os.environ.get("DATA_DIR", "data"))


def data_version(corpus: bool) -> dict:
    return {
        "kb_generation": _kb_generation() if corpus else None,
        "rules_hash": rules_hash(data_dir().resolve()),
    }


@lru_cache
def rules_hash(root: Path) -> str:
    manifest = root / "manifest.json"
    if manifest.is_file():
        return json.loads(manifest.read_text(encoding="utf-8"))["rules_hash"]
    files = [
        p
        for p in root.rglob("*")
        if p.is_file() and not any(part.startswith(".") for part in p.relative_to(root).parts)
    ]
    if not files:
        raise FileNotFoundError("no data files")
    lines = [
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(root).as_posix()}\n"
        for p in sorted(files, key=lambda p: p.relative_to(root).as_posix())
    ]
    return "sha256:" + hashlib.sha256("".join(lines).encode()).hexdigest()


def _kb_generation() -> int:
    from engines.cve.corpus_query import current_generation

    return current_generation()
