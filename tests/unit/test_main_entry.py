"""Unit tests for CLI entry routing via src.main."""

import sys
from typing import Any

import pytest

from src.main import main


def test_missing_command_prints_usage(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["will-encrypt"])

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Commands" in captured.out


def test_init_command_forwarding(monkeypatch) -> None:
    recorded: tuple[Any, ...] | None = None

    def fake_init(k, n, vault_path, force, import_shares, source_vault):
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
def test_handler_routing(command, argv_tail, handler_name, expected_args, monkeypatch):
    recorded: tuple[Any, ...] | None = None

    def fake_handler(*args):
        nonlocal recorded
        recorded = args
        return 0

    monkeypatch.setattr(f"src.main.{handler_name}", fake_handler)
    monkeypatch.setattr(sys, "argv", ["will-encrypt", command, *argv_tail])

    exit_code = main()

    assert exit_code == 0
    assert recorded == expected_args
