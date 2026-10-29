"""Static checks for the architecture's dependency rules.

The SDK must not import core or service implementations, so defenses written
against it stay independent of them.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parents[2] / "src" / "mcp_security_proxy"
PACKAGE = "mcp_security_proxy"


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module)
    return modules


def _internal_imports_outside(directory: Path, allowed_prefix: str) -> list[str]:
    violations = []
    for path in sorted(directory.rglob("*.py")):
        for module in _imported_modules(path):
            if module.startswith(f"{PACKAGE}.") and not module.startswith(allowed_prefix):
                violations.append(f"{path.relative_to(PACKAGE_ROOT)} imports {module}")
    return violations


@pytest.mark.parametrize("directory", ["sdk"])
def test_sdk_imports_only_itself(directory: str) -> None:
    assert _internal_imports_outside(PACKAGE_ROOT / directory, f"{PACKAGE}.sdk") == []
