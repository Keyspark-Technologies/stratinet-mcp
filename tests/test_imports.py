import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("server", "common", "engines")
ALLOWED_THIRD_PARTY = frozenset({"mcp", "psycopg", "starlette", "uvicorn", "yaml"})
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


def defined_in(init, name):
    for node in ast.parse(init.read_text(encoding="utf-8")).body:
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name == name
        ):
            return True
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id == name for t in targets):
                return True
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if any((a.asname or a.name.split(".")[0]) == name for a in node.names):
                return True
    return False


def resolves(path, level, module, names):
    base = path.parent
    for _ in range(level - 1):
        base = base.parent
    if module:
        target = base.joinpath(*module.split("."))
        return target.with_suffix(".py").is_file() or (target / "__init__.py").is_file()
    init = base / "__init__.py"
    return all(
        n == "*"
        or (base / f"{n}.py").is_file()
        or (base / n / "__init__.py").is_file()
        or (init.is_file() and defined_in(init, n))
        for n in names
    )


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
        f"{path.relative_to(ROOT)}:{line} imports {'.' * level}{module} {', '.join(names)}"
        for path in sources()
        for line, level, module, names in imports(path)
        if level > 0 and not resolves(path, level, module, names)
    ]
    assert found == []
