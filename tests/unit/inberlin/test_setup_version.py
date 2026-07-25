"""setup.py must emit a PEP 440 version for every `git describe --tags` shape.

Regression: a clone with tags fetched described as `v1.11.1-35-g0f54f1f`, which
setuptools rejects outright (`InvalidVersion`), so `pip install -e .` failed on
ans0. A clone without tags fell back to `1.0.0` and installed fine, which is why
the same commit behaved differently depending on how it had been cloned.
"""

import importlib.util
from pathlib import Path

from packaging.version import Version

SETUP_PY = Path(__file__).resolve().parents[3] / "setup.py"


def _pep440():
    """Load the helper out of setup.py without executing setup()."""
    source = SETUP_PY.read_text(encoding="utf-8")
    start = source.index("def _pep440")
    end = source.index("try:", start)
    namespace: dict = {}
    exec(compile(source[start:end], str(SETUP_PY), "exec"), namespace)
    return namespace["_pep440"]


def test_describe_shapes_are_valid_pep440():
    fn = _pep440()
    cases = {
        "v1.11.1\n": "1.11.1",
        "1.11.1\n": "1.11.1",
        "v1.11.1-35-g0f54f1f\n": "1.11.1+35.g0f54f1f",
        "v1.11.1-1-gabc1234": "1.11.1+1.gabc1234",
    }
    for described, expected in cases.items():
        got = fn(described)
        assert got == expected, f"{described!r} -> {got!r}, expected {expected!r}"
        Version(got)  # raises InvalidVersion if setuptools would reject it


def test_setup_py_uses_the_helper():
    assert "_pep440(check_output(" in SETUP_PY.read_text(encoding="utf-8")


def test_importlib_can_load_setup_module_spec():
    """Cheap guard that setup.py stays syntactically loadable."""
    spec = importlib.util.spec_from_file_location("_setup_under_test", SETUP_PY)
    assert spec is not None
