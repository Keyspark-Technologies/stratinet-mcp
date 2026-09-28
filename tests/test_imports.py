import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("server", "common", "engines")
ALLOWED_THIRD_PARTY = frozenset({"mcp", "starlette", "uvicorn"})
ALLOWED = frozenset(sys.stdlib_module_names) | frozenset(PACKAGES) | ALLOWED_THIRD_PARTY


def sources():
    return sorted(p for package in PACKAGES for p in (ROOT / package).rglob("*.py"))


def imports(path):
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, 0, alias.name, ()
        elif isinstance(node, ast.ImportFrom):
            names = tuple(alias.name for alias in node.names)
            yield node.lineno, node.level, node.module or "", names


def resolves(path, level, module, names):
    base = path.parent
    for _ in range(level - 1):
        base = base.parent
    target = base.joinpath(*module.split(".")) if module else base
    if target.with_suffix(".py").is_file() or (target / "__init__.py").is_file():
        return True
    return not module and all((base / f"{n}.py").is_file() for n in names)


def test_there_is_code_to_check():
    assert sources()


def test_every_absolute_import_is_allowed():
    found = [
        f"{path.relative_to(ROOT)}:{line} imports {module}"
        for path in sources()
        for line, level, module, _ in imports(path)
        if level == 0 and module.split(".")[0] not in ALLOWED
    ]
    assert found == []


def test_every_relative_import_resolves_inside_the_repo():
    found = [
        f"{path.relative_to(ROOT)}:{line} imports {'.' * level}{module}"
        for path in sources()
        for line, level, module, names in imports(path)
        if level > 0 and not resolves(path, level, module, names)
    ]
    assert found == []
