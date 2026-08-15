from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

_FORBIDDEN_ROOTS = frozenset({"assay", "writ", "sklearn", "scipy", "numpy"})


def _imported_modules(path: Path) -> Iterator[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            yield node.module


def _forbidden_imports(path: Path) -> tuple[str, ...]:
    return tuple(
        name for name in _imported_modules(path) if name.partition(".")[0] in _FORBIDDEN_ROOTS
    )


def test_should_keep_the_trust_kernel_free_of_domain_and_scoring_imports() -> None:
    violations = {
        str(path): imports
        for path in Path("src/avow").rglob("*.py")
        if (imports := _forbidden_imports(path))
    }

    assert violations == {}
