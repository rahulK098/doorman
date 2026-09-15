"""ADR-0001: no layer may import another layer.

Layers may import ``doorman.types``, ``doorman.scoring``, ``doorman.canary``,
``doorman.session`` and ``doorman.errors`` — shared, layer-agnostic modules —
but never a sibling under ``doorman.layers``.
"""

import ast
from pathlib import Path

import pytest

LAYERS_DIR = Path(__file__).resolve().parents[1] / "src" / "doorman" / "layers"
LAYER_MODULES = sorted(p for p in LAYERS_DIR.glob("*.py") if p.name != "__init__.py")


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


@pytest.mark.parametrize("module", LAYER_MODULES, ids=lambda p: p.stem)
def test_layer_does_not_import_sibling_layers(module: Path):
    offenders = {n for n in _imports(module) if n.startswith("doorman.layers")}
    assert not offenders, f"{module.name} imports sibling layer(s): {sorted(offenders)}"


def test_layers_do_not_import_guard():
    for module in LAYER_MODULES:
        assert "doorman.guard" not in _imports(module), module.name
        assert "doorman" not in _imports(module), f"{module.name} imports the package root"
