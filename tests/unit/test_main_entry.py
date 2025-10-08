"""Unit tests for CLI entry routing via src.main."""

import sys
from typing import Any

import pytest

from src.main import main


def test_missing_command_launches_interactive(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that missing command launches interactive mode."""
    interactive_called = False

    def fake_interactive() -> int:
        nonlocal interactive_called
        interactive_called = True
        return 0

    monkeypatch.setattr("src.main.interactive_mode", fake_interactive)
    monkeypatch.setattr(sys, "argv", ["will-encrypt"])

    exit_code = main()

    assert exit_code == 0
    assert interactive_called


def test_init_command_forwarding(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded: tuple[Any, ...] | None = None

    def fake_init(k: int | None, n: int | None, vault_path: str, force: bool, import_shares: list[str] | None, source_vault: str | None) -> int:
        nonlocal recorded
        recorded = (k, n, vault_path, force, import_shares, source_vault)
        return 0

    monkeypatch.setattr("src.main.init_command", fake_init)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "will-encrypt",
            "init",
            "--k",
            "3",
            "--n",
            "5",
            "--vault",
            "vault.yaml",
            "--force",
            "--import-share",
            "1: abandon ability able ...",
            "--import-share",
            "2: about above absent ...",
            "--source-vault",
            "existing.yaml",
        ],
    )

    exit_code = main()

    assert exit_code == 0
    assert recorded == (
        3,
        5,
        "vault.yaml",
        True,
        ["1: abandon ability able ...", "2: about above absent ..."],
        "existing.yaml",
    )


@pytest.mark.parametrize(
    ("command", "argv_tail", "handler_name", "expected_args"),
    [
        (
            "encrypt",
            ["--vault", "vault.yaml", "--title", "Demo", "--message", "Hello"],
            "encrypt_command",
            ("vault.yaml", "Demo", "Hello", False),
        ),
        (
            "decrypt",
            ["--vault", "vault.yaml", "--shares", "1: foo", "2: bar", "3: baz"],
            "decrypt_command",
            ("vault.yaml", ["1: foo", "2: bar", "3: baz"]),
        ),
        (
            "list",
            ["--vault", "vault.yaml", "--format", "json", "--sort", "size"],
            "list_command",
            ("vault.yaml", "json", "size"),
        ),
        (
            "validate",
            ["--vault", "vault.yaml", "--verbose"],
            "validate_command",
            ("vault.yaml", True),
        ),
        (
            "rotate",
            [
                "--vault",
                "vault.yaml",
                "--mode",
                "shares",
                "--new-k",
                "4",
                "--new-n",
                "6",
                "--shares",
                "1: foo",
                "2: bar",
                "3: baz",
            ],
            "rotate_command",
            ("vault.yaml", "shares", 4, 6, ["1: foo", "2: bar", "3: baz"]),
        ),
    ],
)
def test_handler_routing(command: str, argv_tail: list[str], handler_name: str, expected_args: tuple[Any, ...], monkeypatch: pytest.MonkeyPatch) -> None:
    recorded: tuple[Any, ...] | None = None

    def fake_handler(*args: Any) -> int:
        nonlocal recorded
        recorded = args
        return 0

    monkeypatch.setattr(f"src.main.{handler_name}", fake_handler)
    monkeypatch.setattr(sys, "argv", ["will-encrypt", command, *argv_tail])

    exit_code = main()

    assert exit_code == 0
    assert recorded == expected_args
