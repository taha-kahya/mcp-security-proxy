"""Static checks for the architecture's dependency rules.

The SDK must not import core or service implementations, and defenses must
import only the SDK and their own package: never core, services, or another
defense.
"""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[2] / "src" / "mcp_security_proxy"
PACKAGE = "mcp_security_proxy"


def _package_of(path: Path) -> str:
    """The package a module's relative imports resolve against."""
    return ".".join(path.parent.relative_to(PACKAGE_ROOT.parent).parts)


def _imported_modules(path: Path, package: str | None = None) -> set[str]:
    """Every module `path` imports, with relative imports resolved, so a
    `from ..core import x` can't slip past the checks below."""
    package = package if package is not None else _package_of(path)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                modules.add(node.module or "")
                continue
            parts = package.split(".")
            base = ".".join(parts[: len(parts) - (node.level - 1)])
            if node.module:
                modules.add(f"{base}.{node.module}")
            else:  # `from .. import core`: each name may be a module
                modules.update(f"{base}.{alias.name}" for alias in node.names)
    return modules


def _internal_imports_outside(directory: Path, allowed_prefix: str) -> list[str]:
    violations = []
    for path in sorted(directory.rglob("*.py")):
        for module in _imported_modules(path):
            if module.startswith(f"{PACKAGE}.") and not module.startswith(allowed_prefix):
                violations.append(f"{path.relative_to(PACKAGE_ROOT)} imports {module}")
    return violations


def test_sdk_imports_only_itself() -> None:
    assert _internal_imports_outside(PACKAGE_ROOT / "sdk", f"{PACKAGE}.sdk") == []


def _own_package(path: Path) -> str:
    """`defenses/<category>/<name>/...` may import its own `<category>.<name>` package."""
    parts = path.parent.relative_to(PACKAGE_ROOT / "defenses").parts[:2]
    return ".".join([PACKAGE, "defenses", *parts]) if len(parts) == 2 else f"{PACKAGE}.sdk"


def test_defenses_import_only_the_sdk_and_their_own_package() -> None:
    violations = [
        f"{path.relative_to(PACKAGE_ROOT)} imports {module}"
        for path in sorted((PACKAGE_ROOT / "defenses").rglob("*.py"))
        for module in _imported_modules(path)
        if module.startswith(f"{PACKAGE}.")
        and not module.startswith((f"{PACKAGE}.sdk", _own_package(path)))
    ]
    assert violations == []


def test_relative_imports_are_resolved(tmp_path: Path) -> None:
    module = tmp_path / "module.py"
    module.write_text(
        "from ..core.guard import Guard\nfrom .. import services\nfrom .types import Stage\n",
        encoding="utf-8",
    )
    assert _imported_modules(module, f"{PACKAGE}.sdk") == {
        f"{PACKAGE}.core.guard",
        f"{PACKAGE}.services",
        f"{PACKAGE}.sdk.types",
    }
