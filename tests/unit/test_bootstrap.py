"""Unit tests for source-checkout launcher bootstrap."""

from __future__ import annotations

from pathlib import Path

import pytest

from src import bootstrap


def test_parse_requirement_pins_ignores_comments_and_includes() -> None:
    lines = [
        "# runtime dependencies",
        "PyYAML==6.0.3",
        "",
        "-r base.txt",
        "cryptography==48.0.0  # pinned for reproducibility",
    ]

    pins = bootstrap.parse_requirement_pins(lines)

    assert pins == (
        bootstrap.RequirementPin("PyYAML", "6.0.3"),
        bootstrap.RequirementPin("cryptography", "48.0.0"),
    )


def test_missing_requirements_reports_missing_and_mismatched_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed = {
        "PyYAML": "6.0.3",
        "cryptography": "47.0.0",
    }

    def fake_version(name: str) -> str:
        if name not in installed:
            raise bootstrap.PackageNotFoundError
        return installed[name]

    monkeypatch.setattr(bootstrap.metadata, "version", fake_version)
    pins = (
        bootstrap.RequirementPin("PyYAML", "6.0.3"),
        bootstrap.RequirementPin("cryptography", "48.0.0"),
        bootstrap.RequirementPin("pqcrypto", "0.4.0"),
    )

    missing = bootstrap.missing_requirements(pins)

    assert missing == (
        bootstrap.RequirementStatus("cryptography", "48.0.0", "47.0.0"),
        bootstrap.RequirementStatus("pqcrypto", "0.4.0", None),
    )


def test_run_creates_target_venv_and_reexecutes_bootstrap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path
    requirements = root / "requirements.txt"
    requirements.write_text("PyYAML==6.0.3\n", encoding="utf-8")
    created: list[Path] = []
    exec_calls: list[tuple[Path, str, tuple[str, ...]]] = []

    monkeypatch.setattr(bootstrap, "project_root", lambda: root)
    monkeypatch.setattr(bootstrap, "current_executable", lambda: root / "python")
    monkeypatch.setattr(bootstrap, "create_venv", created.append)
    monkeypatch.setattr(
        bootstrap,
        "exec_module",
        lambda python, module, args: exec_calls.append((python, module, tuple(args))),
    )
    monkeypatch.setattr(Path, "exists", lambda path: path == requirements)

    exit_code = bootstrap.run(["--help"])

    assert exit_code == 0
    assert created == [root / ".venv"]
    assert exec_calls == [
        (root / ".venv" / "bin" / "python", "src.bootstrap", ("--help",))
    ]


def test_run_rejects_python_before_3_11(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(bootstrap.sys, "version_info", (3, 10, 13))
    monkeypatch.setattr(bootstrap, "exec_module", lambda *_args: pytest.fail("unexpected exec"))

    exit_code = bootstrap.run([])

    assert exit_code == 1
    assert "Python 3.11+ is required" in capsys.readouterr().err


def test_run_installs_missing_deps_in_target_venv_then_executes_main(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path
    venv_python = root / ".venv" / "bin" / "python"
    requirements = root / "requirements.txt"
    requirements.write_text("PyYAML==6.0.3\n", encoding="utf-8")
    install_calls: list[tuple[Path, Path]] = []
    exec_calls: list[tuple[Path, str, tuple[str, ...]]] = []
    checks = [
        (bootstrap.RequirementStatus("PyYAML", "6.0.3", None),),
        (),
    ]

    monkeypatch.setattr(bootstrap, "project_root", lambda: root)
    monkeypatch.setattr(bootstrap, "current_executable", lambda: venv_python)
    monkeypatch.setattr(bootstrap, "missing_requirements", lambda _pins: checks.pop(0))
    monkeypatch.setattr(
        bootstrap,
        "install_requirements",
        lambda python, path: install_calls.append((python, path)),
    )
    monkeypatch.setattr(
        bootstrap,
        "exec_module",
        lambda python, module, args: exec_calls.append((python, module, tuple(args))),
    )

    exit_code = bootstrap.run(["list", "--vault", "vault.yaml"])

    assert exit_code == 0
    assert install_calls == [(venv_python, requirements)]
    assert exec_calls == [
        (venv_python, "src.main", ("list", "--vault", "vault.yaml"))
    ]


def test_run_returns_failure_when_install_does_not_satisfy_requirements(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path
    venv_python = root / ".venv" / "bin" / "python"
    requirements = root / "requirements.txt"
    requirements.write_text("PyYAML==6.0.3\n", encoding="utf-8")
    unresolved = (bootstrap.RequirementStatus("PyYAML", "6.0.3", None),)

    monkeypatch.setattr(bootstrap, "project_root", lambda: root)
    monkeypatch.setattr(bootstrap, "current_executable", lambda: venv_python)
    monkeypatch.setattr(bootstrap, "missing_requirements", lambda _pins: unresolved)
    monkeypatch.setattr(bootstrap, "install_requirements", lambda _python, _path: None)
    monkeypatch.setattr(bootstrap, "exec_module", lambda *_args: pytest.fail("unexpected exec"))

    exit_code = bootstrap.run([])

    assert exit_code == 1
    assert "Could not satisfy runtime dependencies" in capsys.readouterr().err
