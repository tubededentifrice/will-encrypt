"""Unit tests for dependency age enforcement tooling."""

import importlib.util
import sys
from pathlib import Path

import pytest

TOOL_PATH = Path(__file__).parents[2] / "tools" / "check_dependency_age.py"
SPEC = importlib.util.spec_from_file_location("check_dependency_age", TOOL_PATH)
assert SPEC is not None and SPEC.loader is not None
check_dependency_age = importlib.util.module_from_spec(SPEC)
sys.modules["check_dependency_age"] = check_dependency_age
SPEC.loader.exec_module(check_dependency_age)


def test_parse_requirement_pins_expands_includes(tmp_path: Path) -> None:
    """Requirements parser follows -r includes and records exact pins."""
    base = tmp_path / "requirements.txt"
    dev = tmp_path / "requirements-dev.txt"
    base.write_text("PyYAML==6.0.3\n", encoding="utf-8")
    dev.write_text("-r requirements.txt\npytest==9.0.3\n", encoding="utf-8")

    pins = check_dependency_age.parse_requirement_pins([dev])

    assert [(pin.name, pin.version) for pin in pins] == [
        ("PyYAML", "6.0.3"),
        ("pytest", "9.0.3"),
    ]


def test_parse_requirement_pins_rejects_ranges(tmp_path: Path) -> None:
    """Requirements must use exact pins so pip cannot float to newer releases."""
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("cryptography>=48.0.0\n", encoding="utf-8")

    with pytest.raises(ValueError, match="must be exactly pinned"):
        check_dependency_age.parse_requirement_pins([requirements])


def test_parse_pyproject_pins_checks_all_dependency_sections(tmp_path: Path) -> None:
    """Pyproject parser covers build, runtime, and optional dependency pins."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[build-system]
requires = ["setuptools==82.0.1"]

[project]
dependencies = ["cryptography==48.0.0"]

[project.optional-dependencies]
dev = ["pytest==9.0.3"]
""",
        encoding="utf-8",
    )

    pins = check_dependency_age.parse_pyproject_pins(pyproject)

    assert [(pin.name, pin.version) for pin in pins] == [
        ("setuptools", "82.0.1"),
        ("cryptography", "48.0.0"),
        ("pytest", "9.0.3"),
    ]


def test_dedupe_pins_rejects_conflicting_versions() -> None:
    """Conflicting pins would make the cutoff ambiguous."""
    pins = [
        check_dependency_age.RequirementPin("pytest", "9.0.2", "requirements.txt:1"),
        check_dependency_age.RequirementPin("pytest", "9.0.3", "pyproject.toml:dev"),
    ]

    with pytest.raises(ValueError, match="conflicting pins"):
        check_dependency_age.dedupe_pins(pins)
