"""Guard for a bug class this suite is otherwise blind to.

Development happens on Python 3.14, where PEP 649 defers annotation evaluation,
so a name imported only under `if TYPE_CHECKING:` can be used as a plain runtime
annotation and nothing complains. On Python 3.13 and earlier the annotation is
evaluated when the function is defined, and importing the module raises
NameError. Debian 13 — the deployment target for the IN-Berlin proxy (ans0) —
ships 3.13, so that combination is a production import failure that every test
here would still report green.

Caught for real on 2026-07-25: store.py annotated `identity: Identity` with
Identity imported under TYPE_CHECKING, and the service failed to start on ans0
with `NameError: name 'Identity' is not defined` while all 238 tests passed
locally.

The invariant enforced here is the cheap, interpreter-independent one: a module
that imports anything under TYPE_CHECKING must also request deferred
annotations via `from __future__ import annotations`.
"""

import ast
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[3] / "powerdns_api_proxy"


def _has_future_annotations(tree: ast.Module) -> bool:
    return any(
        isinstance(node, ast.ImportFrom)
        and node.module == "__future__"
        and any(alias.name == "annotations" for alias in node.names)
        for node in tree.body
    )


def _imports_under_type_checking(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        guarded = (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
            isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
        )
        if guarded and any(
            isinstance(child, (ast.Import, ast.ImportFrom)) for child in ast.walk(node)
        ):
            return True
    return False


def test_type_checking_imports_require_deferred_annotations():
    offenders = []
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if _imports_under_type_checking(tree) and not _has_future_annotations(tree):
            offenders.append(str(path.relative_to(PACKAGE.parent)))

    assert not offenders, (
        "these modules import names under TYPE_CHECKING but do not use "
        "`from __future__ import annotations`, so they fail to import on "
        "Python <= 3.13 (the deployment target): " + ", ".join(offenders)
    )


def test_guard_detects_a_violation():
    """The check above is only useful if it can actually fail."""
    bad = ast.parse(
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    from x import Y\n"
        "def f(a: Y) -> None: ...\n"
    )
    assert _imports_under_type_checking(bad)
    assert not _has_future_annotations(bad)

    good = ast.parse(
        "from __future__ import annotations\n"
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    from x import Y\n"
    )
    assert _has_future_annotations(good)
